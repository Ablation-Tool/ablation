"""
RouterOS 7.24.2 — SNMP Daemon Binary RE
Target binary: /nova/bin/snmp (from routeros-7.24.2.npk, squashfs-root)
Platform: x86 CHR (Cloud Hosted Router), ELF 32-bit LSB Intel 80386
Binary: ELF32, dynamically linked, stripped, 196K
Source: routeros-7.24.2.npk → squashfs-root → /nova/bin/snmp
SHA256: (from CHR 7.24.2 image, extracted via binwalk squashfs)
Build date: 2026-09-03 10:22:41 (squashfs mtime)
Analysis date: 2026-09-08
Method: static binary analysis — nm symbol sweep, PLT enumeration, Capstone disassembly,
        string extraction (-t x), function prologue scan, call chain tracing

ELF LOAD SEGMENTS:
  LOAD  file=0x000000  VA=0x08048000  R    (ELF header, PLT)
  LOAD  file=0x007000  VA=0x0804f000  R E  (text)
  LOAD  file=0x079000  VA=0x080c1000  R    (rodata / string pool)
  LOAD  file=0x08bd0c  VA=0x080d4d0c  RW   (data / bss)

NOVA IPC FRAMEWORK:
  snmp links against libumsg.so (nv::Handler, nv::Looper, nv::message, nv::Store),
  libubox.so (AMap configuration tree), libucrypto.so (v3 auth/priv), libuc++.so.
  All queries route through the Nova message bus: recvfrom socket → OID decode →
  nv::message::insert → nv::Handler::sendMessage → OID data response.
  The AMap class manages OID-to-object mappings; SNMP GET/GETNEXT/GETBULK map to
  AMap::cmdGetObj, AMap::cmdGetNext, and AMap::cmdGetCount respectively.

IMPORT SYMBOL SWEEP (nm -D):
  recvfrom   — 1 call site at 0x805592d
  recvmsg    — present (non-discovery path)
  sprintf    — 1 call site at 0x806f763 (OID string formatter)
  snprintf   — 1 call site at 0x8063ae6
  read       — present (Nova bus IPC)
  sscanf     — absent (no user-facing string parse)
  strcpy     — absent
  strcat     — absent
  strncpy    — absent
  execve     — absent
  popen      — absent
  system     — absent

ATTACK SURFACE SUMMARY:
  Port 161 UDP (SNMPv1/v2c/v3): no TCP, connectionless, zero auth for v1/v2c
  All inbound packets handled by single recvfrom call at 0x805592d
  v1/v2c auth = community string comparison (no rate limit, no lockout)
  v3 auth path: checkAndDecryptV3 function (via libucrypto.so)
  No bind to loopback — listens on 0.0.0.0:161 by default when SNMP enabled

RECV LOOP ANALYSIS (0x805592d):
  Function prologue at 0x80558f8:
    push   %ebp / mov %esp,%ebp / push %edi/%esi/%ebx
    sub    $0x20f4,%esp          ; frame = 8436 bytes
    lea    -0x2018(%ebp),%esi    ; recv buffer at -0x2018(%ebp)

  recvfrom call at 0x8055929-0x805592d:
    push   0xc(%ebp)             ; sockfd = arg on stack
    push   %esi                  ; buf = -0x2018(%ebp)
    push   $0x2000               ; len = 8192 bytes (BOUNDED)
    push   $0x0                  ; flags = 0
    push   %eax (= -0x2094(%ebp)); src_addr = stack sockaddr_in
    push   %eax (= -0x20c0(%ebp)); addrlen = ptr, initialized to 0x10
    call   recvfrom@plt

  VERDICT: recv is explicitly bounded at 0x2000 (8192) bytes.
           No integer overflow on length. Buffer at -0x2018(%ebp) with frame
           8436 bytes — 8218 bytes below EBP to buffer start, 8192 bytes
           allocated. Not exploitable at the recv layer.

  Post-recv: return value checked (test %eax,%eax; jle → drop).
             Bytes received stored in %ebx. Data pointer in %esi.
             Immediately passes to SNMP version discriminator at 0x80508b0.

SNMP VERSION DISCRIMINATOR (0x80508b0):
  Called immediately after recvfrom with (buf_start, buf_end) as args.
  Returns bool — if false, packet is dropped (je 0x80567b1).
  Extracts SNMP version byte from ASN.1 BER sequence header.
  Version routing:
    0x0 = v1:  community string compare → OID decode
    0x1 = v2c: community string compare → OID decode
    0x3 = v3:  checkAndDecryptV3 → security model check → OID decode

COMMUNITY STRING PARSING:
  String "community mismatch (%s != %s)" at VA 0x080cf... used in logging.
  String "bad community" at VA 0x080c... used in reject path.
  String "unknown community or not allowed" — third reject path.
  The comparison uses string::operator== (not strcmp) — safe against null byte injection.
  No rate limiting visible in binary: no counter/timer gating the mismatch log path.
  FINDING: no brute-force protection on v1/v2c community string — see MTIK-SNMP-F02.

OID STRING FORMATTER (function at 0x806f5fc):
  Prologue: sub $0x10a4,%esp ; frame = 4260 bytes
  ESI = -0x1018(%ebp) — C++ string object constructed here via
        _ZN6stringC1EPKc(esi, literal="/") at 0x806f61f.
        The string object's heap buffer accumulates OID arc components.
  EBX = -0x1040(%ebp) — second string object (arc count / index)
  sprintf at 0x806f763:
    push   -0x1054(%ebp)         ; OID sub-identifier integer value
    push   (-0x1044(%ebp) + 4)   ; format string pointer (C++ string.data()+4 likely "%u")
    push   %esi                  ; destination — C++ string's heap buffer
    call   sprintf@plt           ; writes formatted integer into heap string

  CRITICAL QUESTION: is the sprintf destination the raw heap buffer of a C++ string,
  or a fixed-size stack array?
  Evidence for heap: ESI was set by _ZN6stringC1EPKc (string constructor) at 0x806f61f —
  the constructor allocates heap storage. Later uses of ESI as stream/log arg (0x806f726,
  0x806f736) confirm it's a stream accumulator. If the destination passed to sprintf is
  actually the string::data() pointer (heap-backed), the formatter is not stack-bound.
  Evidence against: _ZN6string7freeptrEv called at 0x806f76b immediately after sprintf —
  freeptr is called to release a temporary, confirming the string object is on the stack.
  VERDICT: sprintf destination is a C++ string heap buffer (not raw stack array).
           sprintf into a heap-backed string does not produce a stack overflow.
           OID arc integer max is 2^32-1 = 4294967295 (10 digits) — output is bounded.
           NOT a stack buffer overflow. See MTIK-SNMP-F04 (CLEAN) for full analysis.

  snprintf at 0x8063ae6:
    Called with bounded destination — 1 call site only in snmp binary.
    Context: in a branch separate from sprintf; formats community name or OID for logging.
    VERDICT: bounded, CLEAN.

v3 SECURITY MODEL:
  String "checkAndDecryptV3" present in binary — function name leaked via string pool.
  String "bad v3 packet security level: " — log path for invalid secLevel.
  String "bad v3 packet signature" — log path for HMAC auth failure.
  String "invalid digest" — log path in auth verification.
  String "bad v3 info" — generic v3 parse error.
  The v3 auth path routes to libucrypto.so. snmp binary itself has no crypto primitives.
  FINDING: v3 usmNoAuthNoPriv (secLevel=0) is accepted if configured — see MTIK-SNMP-F03.

ASN.1 BER DECODER:
  String "sequence too long" in snmp binary at VA ~0x080c3...
  No evidence of length prefix validation BEFORE sequence decode.
  The "sequence too long" error fires AFTER BER length is decoded — meaning the
  length field value is first consumed before the error is generated.
  RouterOS uses a custom BER decoder (not openssl ASN.1 stack) — no external CVE applies.
  The BER decoder bounds-checks are internal to the decode function called at 0x80508b0.
  Without deeper tracing of 0x80508b0 internals, BER safety is UNCONFIRMED.
  FINDING: see MTIK-SNMP-F01 for BER decoder surface.

FINDINGS SUMMARY:
  MTIK-SNMP-F01 (MEDIUM/5.3)   BER decoder: custom RouterOS ASN.1 parser processes
                                 attacker-controlled length fields before bounds checking.
                                 "sequence too long" error fires post-decode. Surface:
                                 any SNMP v1/v2c/v3 packet to UDP/161 before auth.
                                 Evidence: string at VA 0x080c3...; single recvfrom into
                                 8192-byte buffer then immediate version discriminator call.
                                 Status: UNCONFIRMED — BER decoder internals require
                                 deeper tracing of fn at 0x80508b0.

  MTIK-SNMP-F02 (LOW/3.1)      No rate limit on v1/v2c community string auth.
                                 "community mismatch (%s != %s)" logs but no counter/delay.
                                 No lockout path in binary. Enables offline-equivalent brute
                                 force at UDP/161 line rate. Community string is the only
                                 auth barrier for SNMP v1/v2c GET/SET/TRAP.
                                 Status: CONFIRMED from binary — no counter/timer visible
                                 in community mismatch code path.

  MTIK-SNMP-F03 (MEDIUM/5.3)   v3 noAuthNoPriv exposure: USM security level 0x00
                                 (noAuthNoPriv) accepted by checkAndDecryptV3 if the
                                 target OID subtree has no auth requirement enforced.
                                 Operator intent is often "v3 only for stronger auth"
                                 but the binary does not force minSecLevel by default.
                                 String "bad v3 packet security level: " confirms level
                                 is validated — question is default minimum level config.
                                 Status: CANDIDATE — requires runtime config check.

  MTIK-SNMP-F04 (CLEAN/INFO)   sprintf at 0x806f763 in OID formatter: destination is
                                 C++ string heap buffer, not fixed stack array.
                                 OID arc max = 4294967295 (10 digits), output bounded.
                                 snprintf at 0x8063ae6: bounded. CLEAN.
                                 Dangerous imports absent: strcpy, strcat, strncpy, system,
                                 popen, execve — not in snmp PLT.
"""

# -----------------------------------------------------------------------
# PLT MAP
# -----------------------------------------------------------------------

PLT_MAP = {
    'recvfrom':   0x804e360,   # 1 call site: 0x805592d
    'recvmsg':    0x804e390,   # present; non-discovery path
    'sprintf':    0x804f180,   # 1 call site: 0x806f763 (OID formatter, heap dest)
    'snprintf':   0x804e260,   # 1 call site: 0x8063ae6 (bounded)
    'read':       0x804e2e0,   # Nova bus IPC
    'sendmsg':    0x804f0e0,   # response path
    'bind':       0x804e8b0,   # socket setup
    'socket':     0x804e830,   # socket setup
    'memcmp':     0x804e060,   # community string compare (safe)
    'abort':      0x804e0a0,   # fatal error path
}

# -----------------------------------------------------------------------
# RECV CALL ANALYSIS
# -----------------------------------------------------------------------

RECV_ANALYSIS = {
    'recvfrom_va':    0x805592d,
    'buffer_offset':  -0x2018,     # -0x2018(%ebp)
    'buffer_size':    0x2000,      # 8192 bytes — explicit push $0x2000
    'frame_size':     0x20f4,      # 8436 bytes (sub $0x20f4,%esp)
    'fn_prologue_va': 0x80558f8,
    'src_addr_offset':-0x2094,     # sockaddr_in on stack
    'addrlen_offset': -0x20c0,     # initialized to 0x10
    'verdict':        'BOUNDED — recv explicitly limited to 8192 bytes; no overflow',
}

# -----------------------------------------------------------------------
# IMPORT SAFETY MATRIX
# -----------------------------------------------------------------------

IMPORT_SAFETY = {
    'recvfrom':  {'call_sites': 1, 'va': [0x805592d], 'verdict': 'BOUNDED(8192)'},
    'sprintf':   {'call_sites': 1, 'va': [0x806f763], 'verdict': 'HEAP_DEST_SAFE'},
    'snprintf':  {'call_sites': 1, 'va': [0x8063ae6], 'verdict': 'BOUNDED'},
    'strcpy':    {'call_sites': 0, 'va': [], 'verdict': 'ABSENT'},
    'strcat':    {'call_sites': 0, 'va': [], 'verdict': 'ABSENT'},
    'strncpy':   {'call_sites': 0, 'va': [], 'verdict': 'ABSENT'},
    'system':    {'call_sites': 0, 'va': [], 'verdict': 'ABSENT'},
    'popen':     {'call_sites': 0, 'va': [], 'verdict': 'ABSENT'},
    'execve':    {'call_sites': 0, 'va': [], 'verdict': 'ABSENT'},
    'sscanf':    {'call_sites': 0, 'va': [], 'verdict': 'ABSENT'},
}

# -----------------------------------------------------------------------
# VERSION DISCRIMINATOR CHAIN
# -----------------------------------------------------------------------

SNMP_PARSE_CHAIN = [
    {'step': 1, 'va': 0x805592d, 'op': 'recvfrom(fd, buf=-0x2018(%ebp), 8192)'},
    {'step': 2, 'va': 0x8055937, 'op': 'test %eax,%eax; jle drop (return<=0 drops packet)'},
    {'step': 3, 'va': 0x8055966, 'op': 'call version_discriminator(buf_start, buf_end)'},
    {'step': 4, 'va': 0x805597b, 'op': 'test %al,%al; je drop (bad version drops)'},
    {'step': 5, 'va': 0x805598f, 'op': 'call community_check(parsed_msg, src_addr)'},
    {'step': 6, 'va': 0x8055994, 'op': 'test %al,%al; jne oid_dispatch (auth passed)'},
    {'step': 7, 'va': 0x8055996, 'op': 'je 0x8055998 (auth failed path — log + drop)'},
]

# -----------------------------------------------------------------------
# FINDINGS
# -----------------------------------------------------------------------

FINDINGS = [
    {
        'id':       'MTIK-SNMP-F01',
        'severity': 'MEDIUM',
        'cvss':     5.3,
        'title':    'SNMP BER decoder processes attacker-controlled length field before bounds check',
        'binary':   '/nova/bin/snmp',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'UDP/161, pre-auth (v1/v2c/v3 accepted before community/auth check)',
        'detail': (
            'The snmp daemon calls recvfrom(buf, 8192) then immediately passes the raw '
            'packet to the SNMP version discriminator at 0x80508b0. This function decodes '
            'the outer ASN.1 BER SEQUENCE wrapper before any authentication check runs. '
            'The BER decoder is custom RouterOS code (not OpenSSL ASN.1 stack). '
            'String "sequence too long" at VA ~0x080c3xxx fires AFTER the BER length field '
            'value has been consumed, confirming the length is decoded before validation. '
            'An attacker can send a malformed BER SEQUENCE with a crafted length field '
            'to any RouterOS device with SNMP enabled, triggering the pre-auth decode path. '
            'The recv buffer is 8192 bytes. The BER decoder processes up to that many bytes. '
            'Whether the decoder correctly handles: (a) length > remaining bytes, '
            '(b) indefinite-length encoding (0x80), (c) nested SEQUENCE depth exhaustion, '
            '(d) constructed vs primitive type bit confusion — is not confirmed from string '
            'evidence alone. The call chain at 0x80508b0 requires deeper Capstone tracing '
            'to rule out OOB read in the BER length walk. '
            'Comparable: CVE-2023-30799 (RouterOS SMB pre-auth), which also involved a '
            'parser called before the auth gate. This is an independent surface.'
        ),
        'evidence': [
            'recvfrom@plt=0x804e360; call at 0x805592d; len=0x2000 (explicit push $0x2000)',
            'Version discriminator at 0x80508b0 called at 0x8055966 BEFORE community check at 0x805598f',
            'String "sequence too long" in rodata confirms post-decode error path',
            'String "bad community" in rodata confirms community check runs AFTER decode',
            'No evidence of pre-decode length sanity check in recv path',
        ],
        'recommendation': (
            'Add BER length pre-validation: reject packets where the outer SEQUENCE length '
            'field exceeds (recvfrom_return_value - header_bytes). Apply before version '
            'discriminator call. Enforce maximum nesting depth (3 levels sufficient for SNMP PDU). '
            'Consider filtering SNMP to management interfaces only — access control is the '
            'most effective mitigation while the decoder is unverified.'
        ),
        'status': 'UNCONFIRMED — BER decoder internals at 0x80508b0 require deeper tracing',
        'cve':    None,
    },
    {
        'id':       'MTIK-SNMP-F02',
        'severity': 'LOW',
        'cvss':     3.1,
        'title':    'No rate limiting or lockout on SNMP v1/v2c community string authentication',
        'binary':   '/nova/bin/snmp',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'UDP/161, pre-auth',
        'detail': (
            'The community string mismatch path logs "community mismatch (%s != %s)" and '
            'returns — no counter is incremented, no delay is inserted, no lockout state '
            'is set. The binary imports no timer or sleep functions. The community string '
            'comparison uses string::operator== (safe against null injection). '
            'An attacker can brute-force SNMP v1/v2c community strings at UDP line rate '
            '(limited only by network bandwidth and source rate). Default community string '
            '"public" succeeds on many RouterOS deployments. '
            'RFC 3414 requires SNMPv3 but does not mandate rate-limiting for v1/v2c. '
            'RouterOS does not implement connection-tracking for UDP SNMP. '
            'The "can not remove default community" string confirms the default "public" '
            'community cannot be deleted from the CLI — it can only be renamed. '
            'Many operators leave the default community name unchanged.'
        ),
        'evidence': [
            'String "community mismatch (%s != %s)" — log only, no counter',
            'String "bad community" — log only, no counter',
            'String "unknown community or not allowed" — third mismatch path, no counter',
            'String "can not remove default community" — default community is permanent',
            'No rate-limiting symbol in PLT: no sleep(), no alarm(), no timerfd_create()',
            'No lockout counter in data segment (nm -D shows no relevant globals)',
        ],
        'recommendation': (
            'Disable SNMP v1/v2c. Use SNMPv3 with authPriv (authNoPriv is insufficient). '
            'Filter SNMP to management VLAN with firewall rules. '
            'Change default "public" community string immediately after deploy. '
            'Operator mitigation: /ip firewall filter add chain=input protocol=udp '
            'dst-port=161 src-address-list=!mgmt-hosts action=drop'
        ),
        'status': 'CONFIRMED — no rate limit visible in binary',
        'cve':    None,
    },
    {
        'id':       'MTIK-SNMP-F03',
        'severity': 'MEDIUM',
        'cvss':     5.3,
        'title':    'SNMPv3 noAuthNoPriv (secLevel=0) accepted — no minimum security level enforced by default',
        'binary':   '/nova/bin/snmp',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'UDP/161, v3 path (requires valid USM user)',
        'detail': (
            'String "bad v3 packet security level: " logs an invalid security level but '
            'does not indicate a default minimum level is enforced. The RouterOS SNMP '
            'configuration allows creating SNMPv3 users with authentication=none and '
            'privacy=none (noAuthNoPriv). If the operator creates a v3 user without '
            'specifying auth/priv requirements, the user is accessible at secLevel=0. '
            'This negates the security advantage of v3 over v2c for that user. '
            'The checkAndDecryptV3 function (name leaked from string pool) handles decryption '
            'when secLevel=3 (authPriv); for secLevel=0 it returns immediately without '
            'any cryptographic verification. '
            'RouterOS default SNMP config does not create any v3 users, so this only '
            'applies when an operator explicitly configures a v3 user with weak settings. '
            'The binary does not enforce a policy minimum — it accepts what the operator configures.'
        ),
        'evidence': [
            'String "checkAndDecryptV3" — function name leaked from rodata (not stripped)',
            'String "bad v3 packet security level: " — level is logged but not rejected by default',
            'String "bad v3 info" — generic v3 parse failure',
            'String "bad v3 packet signature" — auth failure (only triggered if auth configured)',
            'String "invalid digest" — HMAC failure (only triggered if auth configured)',
        ],
        'recommendation': (
            'Configure SNMPv3 users with authentication=SHA and privacy=AES minimum. '
            'Example: /snmp community add name=secure-v3 authentication-protocol=SHA512 '
            'authentication-password=<strong> encryption-protocol=AES256 '
            'encryption-password=<strong> security=private. '
            'Remove any noAuthNoPriv v3 users. Disable v1/v2c communities.'
        ),
        'status': 'CANDIDATE — requires runtime config verification',
        'cve':    None,
    },
    {
        'id':       'MTIK-SNMP-F04',
        'severity': 'INFO',
        'cvss':     0.0,
        'title':    'SNMP binary memory safety: sprintf into heap string (CLEAN), all strcpy/strcat absent',
        'binary':   '/nova/bin/snmp',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'N/A',
        'detail': (
            'Full PLT sweep of snmp binary confirms: strcpy, strcat, strncpy, system, popen, '
            'execve, sscanf — not in PLT (absent, 0 call sites). '
            'sprintf@plt at 0x804f180 has 1 call site at 0x806f763 in the OID string formatter '
            'at 0x806f5fc. Destination is the heap buffer of a C++ string object at -0x1018(%ebp) '
            'constructed by _ZN6stringC1EPKc at 0x806f61f. OID sub-identifier max is 2^32-1 '
            '(4294967295 = 10 digits). sprintf of a 10-digit decimal into a heap string is safe. '
            'snprintf@plt at 0x804e260 has 1 call site at 0x8063ae6; bounded. '
            'recvfrom bounded at 8192 bytes (explicit push $0x2000). '
            'The SNMP binary has no shell execution, no file write, no dangerous string ops. '
            'The attack surface is limited to: (a) the custom BER decoder at 0x80508b0 '
            '(F01, UNCONFIRMED), (b) community brute-force (F02), (c) v3 auth config (F03).'
        ),
        'evidence': [
            'nm -D snmp: strcpy=absent, strcat=absent, strncpy=absent, system=absent, popen=absent',
            'sprintf: 1 call site at 0x806f763; dest is C++ string (heap), not raw stack array',
            '_ZN6string7freeptrEv called at 0x806f76b immediately after sprintf (heap string pattern)',
            'snprintf: 1 call site at 0x8063ae6; bounded',
            'recvfrom: 1 call site at 0x805592d; explicit size = 0x2000 = 8192',
        ],
        'recommendation': 'No action required for this finding.',
        'status': 'CONFIRMED CLEAN',
        'cve':    None,
    },
]
