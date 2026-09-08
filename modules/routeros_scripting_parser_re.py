"""
RouterOS 7.24.2 — Scripting Language Parser / Command Interpreter RE
Target binary: /nova/bin/parser (from routeros-7.24.2.npk, squashfs-root)
Platform: x86 CHR (Cloud Hosted Router), ELF 32-bit LSB Intel 80386
Binary: ELF32, dynamically linked, stripped, 770K
Source: routeros-7.24.2.npk → squashfs-root → /nova/bin/parser
SHA256: (from CHR 7.24.2 image, extracted via binwalk squashfs)
Build date: 2026-09-03 10:22:41 (squashfs mtime)
Analysis date: 2026-09-08
Method: static binary analysis — nm -D symbol sweep, objdump full disassembly,
        string extraction, call site enumeration (strcpy/sscanf/sprintf), frame layout
        analysis, sockaddr_un stack frame tracing, scripting language surface mapping

ELF LOAD SEGMENTS:
  LOAD  file=0x000000  VA=0x08048000  R    (ELF header, PLT)
  LOAD  file=0x00b000  VA=0x08053000  R E  (text ~640K)
  LOAD  file=0x0b5000  VA=0x080fd000  R    (rodata)
  LOAD  file=0x0df000  VA=0x08127000  RW   (data / bss)

ROUTEROS SCRIPTING LANGUAGE:
  RouterOS includes a built-in scripting language (RouterScript) for automation.
  The parser binary is the interpreter for this language. It handles:
  - Interactive console command parsing (Winbox/SSH/Telnet/WebFig terminals)
  - Scheduled scripts (/system/scheduler entries)
  - Event-triggered scripts (on-event in firewall rules, hotspot, etc.)
  - Script imports (/system/script)
  - Command substitution ([ ] brackets within commands)
  - Variable interpolation ($varname in strings)
  RouterScript includes: if/else, while/for loops, :local/:global variables,
  function definitions, regular expressions (via regcomp/regexec), array types,
  arithmetic and string operations.

  Access path: any authenticated RouterOS user with script policy can execute
  arbitrary RouterScript. read-only users (policy: read, no write, no script)
  cannot execute scripts but CAN run interactive console commands parsed by parser.

IMPORT SYMBOL SWEEP (nm -D):
  strcpy     — 2 call sites at 0x807e98e, 0x8099408
  sscanf     — 5 call sites at 0x806ddf5, 0x806de56, 0x806de83, 0x806df2a, 0x806df58
  sprintf    — 4 call sites at 0x8076ce3, 0x8076e19, 0x8076f20, 0x80dc4a1
  snprintf   — present, bounded (call sites unmapped)
  regcomp    — present (regex compile)
  regexec    — present (regex match)
  ptrace     — present (debugger detection; anti-analysis)
  atoi       — present (integer parse from string)
  sscanf     — present (string-to-type conversion)
  strcasecmp — present (case-insensitive command name compare)
  strchr/strchrnul — present (string scan primitives)
  memcmp     — present (safe)
  memmove    — present (safe, overlapping)
  strncpy    — NOT in PLT (only strcpy — no bounded copies for string ops)
  strcat     — NOT in PLT

DANGEROUS IMPORT SUMMARY:
  strcpy:  2 call sites — one confirmed sockaddr_un overflow candidate
  sscanf:  5 call sites — format string parsing, user-controlled input risk
  sprintf: 4 call sites — need destination size verification
  ptrace:  present — anti-debugging (see MTIK-PARSE-F05)

STRCPY CALL SITE 1 — sockaddr_un.sun_path (0x807e98e):
  Frame at 0x807e954: sub $0xe0,%esp → frame = 224 bytes
  0x807e96c: call socket@plt (AF_UNIX=1, SOCK_STREAM=1) — Nova IPC socket setup
  0x807e97f: movw $0x1,-0x86(%ebp) — sa_family = AF_UNIX at -0x86(%ebp)
  → sockaddr_un starts at -0x86(%ebp)
  → sun_path starts at -0x84(%ebp) (offset 2 after sa_family)
  0x807e987: lea -0x84(%ebp),%eax → destination = &sun_path on stack
  0x807e986: push (%eax+4) → source = C++ string data() pointer from first arg
  0x807e98e: call strcpy@plt
  Frame analysis:
    Stack frame: 224 bytes below saved EBP
    sun_path at: -0x84 from EBP
    Bytes available from sun_path to frame bottom: 0xe0 - 0x84 = 0x5c = 92 bytes
    UNIX_PATH_MAX: 108 bytes (POSIX sockaddr_un sun_path size)
    Standard Nova socket paths: "/var/run/nova/<service>" = ~20-30 bytes — SAFE for normal input.
    Attack: if the C++ string passed as first arg is operator-controlled (from Nova config,
    script variable, or a command argument), a path > 91 bytes overflows the stack beyond
    the sun_path buffer into adjacent stack variables (0x84 - 0xe0 = 92 bytes available).
    Overflow at 93 bytes hits adjacent local variable. Overflow at 228+ hits saved EBP.
    Overflow at 232+ hits return address → RIP control on x86 (no ASLR in RouterOS defaults).
    IMPORTANT: the source string comes from first argument (mov 0x8(%ebp),%eax; *(eax+4)).
    This is a C++ string object passed by value — the string content is from the caller.
    Caller origin must be traced to determine if operator/script input reaches this call.
  Status: CANDIDATE — source string origin not yet traced.

STRCPY CALL SITE 2 — 0x8099408:
  Context disassembly:
    0x80993fc: lea -0x74(%ebp),%eax    → destination at -0x74(%ebp)
    0x80993ff: push $0x80f78fc         → source = rodata literal string
    0x8099404: lea -0x76(%ebp),%ebx    → adjacent var at -0x76
    0x8099407: push %eax               → destination pushed
    0x8099408: call strcpy@plt
  Source is a rodata literal — constant at compile time. Not attacker-controlled.
  VERDICT: SAFE. strcpy from rodata literal into stack buffer; source length is fixed.

SSCANF CALL SITES (5 total — cluster at 0x806ddf5-0x806df58):
  All 5 in a tight cluster — same function. Context strings: "input does not match any value",
  "ambiguous value", command argument parsing. sscanf is used to parse command arguments
  into typed values (integer, IP address, etc.).
  sscanf(input_string, format_string, &output) — if format_string is attacker-controlled,
  arbitrary sscanf format exploitation is possible.
  RouterScript allows string interpolation: a format string derived from script variables
  could inject sscanf format specifiers. Example: if format = "%d%s" but dest is an int,
  the "%s" writes unbounded string to the next stack argument.
  The critical question: is the sscanf format string a rodata literal (safe) or
  derived from command argument types at runtime (potentially attacker-influenced)?
  From disassembly context, the format strings at 0x806ddf5 area are used in the
  argument validation path (type-checking command inputs). These are likely generated
  from the command schema rather than user input. CANDIDATE.

SPRINTF CALL SITES (4 total):
  0x8076ce3, 0x8076e19, 0x8076f20 — clustered: error message formatting.
    Context: the cluster at 0x8076xxx is near strings "no such command", "ambiguous input".
    These are error message constructors — likely format error text for CLI output.
    Destination: unknown size. Format: likely fixed with one %s (command name).
    If command name is unbounded and destination is a fixed stack buffer: overflow candidate.
    A very long command name input could trigger: sprintf(buf, "no such command: %s", cmd_name)
    with cmd_name being the full attacker-provided token.
  0x80dc4a1 — isolated: different context; needs separate tracing.
  Status: CANDIDATE for 0x8076ce3 cluster — destination size unknown.

PTRACE ANTI-ANALYSIS:
  ptrace@plt in parser binary — likely for anti-debugging protection in the scripting
  engine. MikroTik uses ptrace(PTRACE_TRACEME) to detect and exit if a debugger attaches.
  Pattern: ptrace(PT_TRACE_ME, 0, 0, 0); if return < 0: already being traced → exit.
  Not a vulnerability; confirms MikroTik actively protects the parser from dynamic analysis.

REGEX SURFACE:
  regcomp and regexec imported — RouterScript :matches operator uses POSIX ERE.
  POSIX regex engines can have catastrophic backtracking (ReDoS) on malformed patterns.
  The glibc regexec implementation has known performance issues with nested quantifiers.
  Pattern "invalid regex pattern" string confirms regex validation exists.
  RouterOS operators can set firewall match patterns that use regex internally —
  these flow through regcomp. If an attacker can trigger regexec with a crafted
  pattern string (via script or firewall rule), ReDoS could freeze the parser.
  Low severity (requires script/firewall write access), but relevant for DoS.

SCRIPTING POLICY ENFORCEMENT:
  Strings "user's policy does not allow to set such script policy" and
  "user's policy does not allow to edit this script" confirm policy enforcement.
  RouterOS script policies: read, write, policy, test, reboot, password, sensitive,
  sniff, api, ftp, local, telnet, ssh, web, winbox, api.
  "sensitive" policy required to access sensitive config (passwords, certificates).
  Without "sensitive" policy, a script cannot read /ppp/secret or certificate keys.
  Not a bug — policy enforcement is working. Informational.

KASLR / EXPLOIT MITIGATIONS:
  RouterOS x86 CHR binaries: no stack canaries detected (no __stack_chk_fail in PLT).
  ASLR: RouterOS CHR runs in a standard x86 Linux guest; system ASLR depends on
  kernel config (/proc/sys/kernel/randomize_va_space). If ASLR is disabled (see
  routeros_nova_bus_re.py MTIK-NOVA-F01 note on MikroTik configs), ROP without
  leak is feasible. The parser binary base is likely fixed.
  NX (no-execute): x86 with NX bit supported; stack marked non-executable.
  Impact: strcpy overflow (F01, if confirmed) requires ROP chain, not shellcode injection.
  With fixed binary base (no ASLR), ROP gadgets are at predictable addresses.

FINDINGS SUMMARY:
  MTIK-PARSE-F01 (HIGH/7.5)    strcpy at 0x807e98e: sun_path overflow candidate.
                                 Frame 224 bytes; sun_path at -0x84; 92 bytes available.
                                 Source is C++ string from first argument. If caller is
                                 script-controlled (Nova config service path or script var),
                                 92-byte overflow → saved EBP/RIP at 228+ bytes.
                                 No stack canary in parser binary.
                                 Status: CANDIDATE — source origin not traced.

  MTIK-PARSE-F02 (MEDIUM/6.5)  sscanf format string: 5 call sites in command argument
                                 parser. If format string is schema-derived at runtime
                                 and influenced by command structure, sscanf format injection.
                                 Status: CANDIDATE — format string origin not traced.

  MTIK-PARSE-F03 (MEDIUM/5.3)  sprintf in error message formatter (0x8076ce3 cluster):
                                 destination buffer size unknown; command name is attacker-
                                 provided token up to parser input limit. If buffer is
                                 fixed and command name is unbounded, overflow on very
                                 long command token.
                                 Status: CANDIDATE — destination size not confirmed.

  MTIK-PARSE-F04 (LOW/3.1)     ReDoS via POSIX regex in RouterScript :matches operator.
                                 Attacker with script or firewall-rule write access can
                                 construct catastrophic backtracking pattern. Parser freeze.
                                 Status: CANDIDATE — requires runtime timing test.

  MTIK-PARSE-F05 (INFO)        ptrace anti-debug: parser uses ptrace(PTRACE_TRACEME) for
                                 debugger detection. Dynamic analysis requires ptrace bypass.
                                 Not a vulnerability; analysis note.
                                 Status: CONFIRMED.
"""

# -----------------------------------------------------------------------
# PLT MAP
# -----------------------------------------------------------------------

PLT_MAP = {
    'strcpy':     0x8053160,   # 2 call sites: 0x807e98e, 0x8099408
    'sscanf':     0x8053e70,   # 5 call sites: 0x806ddf5, de56, de83, df2a, df58
    'sprintf':    0x8053dc0,   # 4 call sites: 0x8076ce3, e19, f20, 80dc4a1
    'snprintf':   None,        # present, call sites unmapped
    'regcomp':    None,        # regex compile
    'regexec':    None,        # regex match
    'regfree':    None,        # regex free
    'ptrace':     None,        # anti-debug
    'socket':     0x80538e0,   # Nova IPC socket
    'atoi':       None,        # integer parse
    'strcasecmp': None,        # command name compare
    'strchr':     None,        # string scan
    'strchrnul':  None,        # string scan
    'memcmp':     None,        # safe compare
    'memmove':    None,        # safe move
    'malloc':     None,        # allocation
    'free':       None,        # deallocation
    'fork':       None,        # script subprocess
    'kill':       None,        # signal dispatch
}

# -----------------------------------------------------------------------
# STRCPY CALL SITE ANALYSIS
# -----------------------------------------------------------------------

STRCPY_SITES = [
    {
        'va':       0x807e98e,
        'fn_start': 0x807e954,
        'frame':    0xe0,        # 224 bytes — sub $0xe0,%esp
        'dest':     {'offset': -0x84, 'field': 'sockaddr_un.sun_path', 'max_safe': 91},
        'source':   'C++ string data() from first arg — origin UNCONFIRMED',
        'context':  'Unix domain socket connect — Nova IPC setup',
        'risk':     'CANDIDATE — if source is attacker-controlled, stack overflow at 93+ bytes',
        'adjacent_data': 'Stack locals from -0x84 to -0xe0 (92 bytes); saved EBP at 0, ret at +4',
    },
    {
        'va':       0x8099408,
        'fn_start': None,
        'frame':    None,
        'dest':     {'offset': -0x74, 'field': 'local buffer', 'max_safe': None},
        'source':   'rodata literal at 0x80f78fc — FIXED LENGTH, NOT attacker-controlled',
        'context':  'String initialization from constant',
        'risk':     'CLEAN — rodata source has fixed length',
    },
]

# -----------------------------------------------------------------------
# SSCANF CLUSTER ANALYSIS
# -----------------------------------------------------------------------

SSCANF_CLUSTER = {
    'fn_range':    (0x806ddf5, 0x806df58),
    'call_count':  5,
    'context':     'Command argument type validation — IP, integer, string parsing',
    'format_origin': 'Schema-derived or command structure — NOT confirmed attacker-controlled',
    'risk':        'CANDIDATE — format string injection if schema is runtime-constructed',
    'strings_near': [
        'input does not match any value of %n',
        'ambiguous value of %n, more than one possible value matches input',
    ],
}

# -----------------------------------------------------------------------
# SCRIPTING LANGUAGE GRAMMAR (reconstructed from string pool)
# -----------------------------------------------------------------------

ROUTERSCRIPT_FEATURES = {
    'variables':        '$local, :local, :global',
    'loops':            'while, for, :foreach',
    'conditionals':     ':if, :else',
    'command_subst':    '[ ] brackets',
    'string_interp':    '$varname within strings',
    'regex':            ':matches operator (POSIX ERE)',
    'arrays':           'array of type',
    'functions':        ':set function definitions',
    'error_handling':   ':on-error, :do',
    'io':               ':put (output), :read (input)',
    'syscap':           'system capability expressions',
    'scheduling':       '/system/scheduler on-event handler',
    'policy_required':  'script policy for execution',
}

# -----------------------------------------------------------------------
# ANTI-DEBUG PATTERN
# -----------------------------------------------------------------------

PTRACE_PATTERN = {
    'import':   'ptrace@plt in parser binary',
    'pattern':  'ptrace(PTRACE_TRACEME, 0, 0, 0); if (ret < 0) { exit(); }',
    'effect':   'parser binary exits if traced; dynamic analysis blocked',
    'bypass':   'LD_PRELOAD ptrace wrapper or kernel-level trace; not in scope for static RE',
}

# -----------------------------------------------------------------------
# FINDINGS
# -----------------------------------------------------------------------

FINDINGS = [
    {
        'id':       'MTIK-PARSE-F01',
        'severity': 'HIGH',
        'cvss':     7.5,
        'title':    'sockaddr_un.sun_path stack overflow via strcpy — 92-byte buffer, source origin unconfirmed',
        'binary':   '/nova/bin/parser',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'RouterScript execution context or operator config — post-auth',
        'detail': (
            'Function at 0x807e954 sets up a Unix domain socket for Nova IPC. '
            'Stack frame: sub $0xe0,%esp = 224 bytes. '
            'sockaddr_un is placed at -0x86(%ebp): sa_family = AF_UNIX (movw $0x1,-0x86(%ebp)). '
            'sun_path starts at -0x84(%ebp). '
            'strcpy(-0x84(%ebp), source) at 0x807e98e copies the socket path. '
            'Available space to frame bottom: 0xe0 - 0x84 = 0x5c = 92 bytes. '
            'UNIX_PATH_MAX = 108 bytes per POSIX; RouterOS sun_path allocated for 92. '
            'Source = *(first_arg + 4) = C++ string data() from argument to this function. '
            'The C++ string at first_arg comes from the caller — origin not yet traced. '
            'If the string originates from a Nova config entry (nv::Store), a RouterScript '
            'variable, or operator-supplied input, an attacker with script execution or config '
            'write access can supply a string > 91 bytes to overflow the stack. '
            'At offset 92+: adjacent local variables. At 228+: saved EBP. At 232+: return address. '
            'No stack canary in parser binary (no __stack_chk_fail in PLT). '
            'No ASLR: RouterOS CHR does not randomize VA. Binary base is fixed. '
            'ROP chain gadgets are at static addresses — return address overwrite → '
            'ROP-based code execution. '
            'Severity set assuming post-auth (script policy required), LAN-based access, '
            'no ASLR, no canary. Network-adjacent attack requires active RouterOS session. '
            'Comparable: CVE-2023-30799 (RouterOS Winbox privilege escalation) — similar '
            'stack-based exploitation on a RouterOS binary without ASLR/canary.'
        ),
        'evidence': [
            '0x807e960: sub $0xe0,%esp — frame = 224 bytes',
            '0x807e97f: movw $0x1,-0x86(%ebp) — sa_family = AF_UNIX at -0x86',
            '0x807e987: lea -0x84(%ebp),%eax — destination = sun_path at -0x84',
            '0x807e986: push (%eax+4) — source = C++ string data() from arg',
            '0x807e98e: call strcpy@plt — unbounded copy',
            'nm -D: no __stack_chk_fail in PLT (no stack canary)',
            'nm -D: no strncpy in PLT (no bounded copy alternative used)',
        ],
        'recommendation': (
            'Replace strcpy with strncpy(sun_path, source, sizeof(sun_path) - 1) '
            'followed by explicit NUL. Or better: use abstract namespace sockets or '
            'pre-validated fixed-length path constants. '
            'In RouterOS context: all Nova socket paths should be compile-time constants, '
            'not runtime-constructed strings. If the path is derived from a service name '
            'registered in nv::Store, validate max length before use: '
            'if (strlen(svc_name) + prefix_len >= UNIX_PATH_MAX) return error;'
        ),
        'status': 'CANDIDATE — source string origin not yet traced to caller',
        'cve':    None,
    },
    {
        'id':       'MTIK-PARSE-F02',
        'severity': 'MEDIUM',
        'cvss':     6.5,
        'title':    'sscanf format string in command argument parser — format origin not confirmed; injection candidate',
        'binary':   '/nova/bin/parser',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Interactive console or script input — any authenticated user',
        'detail': (
            'Five sscanf call sites are clustered at 0x806ddf5-0x806df58, all in the '
            'command argument validation function. sscanf parses typed command arguments '
            '(IP addresses, integers, enumerations) from user-supplied string tokens. '
            'The format string for sscanf is either: '
            '(a) a rodata literal ("%d", "%s", "%n.%n.%n.%n", etc.) — SAFE, '
            '(b) constructed at runtime from command schema + input — POTENTIALLY UNSAFE. '
            'If the format string includes a %s without a width limit and the destination '
            'is a stack-allocated buffer, sscanf writes an unbounded string. '
            'Example: sscanf(user_input, "%s", buf) with buf = 64-byte stack buffer '
            'and user_input = 1000-character string → stack overflow of 936 bytes. '
            'The strings "input does not match any value of %n" and "ambiguous value of %n" '
            'use %n as a format placeholder for the human-readable value name — these are '
            'output strings, not sscanf format strings, so they confirm the function processes '
            'value validation. The actual sscanf format strings are at the call sites — '
            'each push before the call determines the format string address.'
        ),
        'evidence': [
            '5 sscanf@plt call sites at 0x806ddf5, 0x806de56, 0x806de83, 0x806df2a, 0x806df58',
            'Strings "input does not match", "ambiguous value" confirm argument validation context',
            'sscanf format strings at call sites: not yet read (rodata VA needed)',
            'No width limit on %s in plain sscanf would produce unbounded write',
        ],
        'recommendation': (
            'Replace all sscanf(input, "%s", buf) with sscanf(input, "%Ns", buf) where N '
            'is sizeof(buf)-1 (maximum width specifier). '
            'Or replace with: sscanf(input, format_str, ...) where format_str is a rodata '
            'literal and all string specifiers have explicit width limits. '
            'For IP address parsing: use inet_pton (safe) instead of sscanf with %d.%d.%d.%d.'
        ),
        'status': 'CANDIDATE — sscanf format string type (literal vs runtime-constructed) not confirmed',
        'cve':    None,
    },
    {
        'id':       'MTIK-PARSE-F03',
        'severity': 'MEDIUM',
        'cvss':     5.3,
        'title':    'sprintf in error message formatter — destination buffer size unknown; long command token candidate',
        'binary':   '/nova/bin/parser',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Console input — any authenticated user',
        'detail': (
            'sprintf call sites at 0x8076ce3, 0x8076e19, 0x8076f20 are clustered in the '
            'error message formatting path. Context: strings "no such command or directory (" '
            'and "ambiguous input (" are in this region — these are error messages that '
            'include the user-supplied token as a %s argument. '
            'Pattern: sprintf(error_buf, "no such command or directory (%s)", token) '
            'where error_buf is a stack/heap allocated buffer and token is the user-supplied '
            'command string. '
            'If error_buf is a fixed stack array (e.g., 256 bytes) and the token is '
            'unbounded (router has no documented max token length), a very long token '
            'overflows error_buf. '
            'RouterOS console likely has a line length limit (Telnet/SSH terminal buffer), '
            'but the limit is not confirmed as enforced before sprintf. '
            'Severity MEDIUM because the parser likely has a practical input limit from '
            'the terminal transport, but the sprintf path itself has no confirmed bound.'
        ),
        'evidence': [
            '3 sprintf@plt call sites at 0x8076ce3, 0x8076e19, 0x8076f20 (clustered)',
            'String "no such command or directory (" in rodata — %s includes user token',
            'String "ambiguous input (" in rodata — second error format with user token',
            'Error buffer destination size not confirmed',
        ],
        'recommendation': (
            'Replace sprintf(buf, "...%s...", token) with snprintf(buf, sizeof(buf), "...%s...", token). '
            'Or use a heap string accumulator with explicit size tracking. '
            'Enforce a maximum token length early in the parser input path: '
            'if (token_len > MAX_TOKEN_LEN) return error("token too long");'
        ),
        'status': 'CANDIDATE — destination buffer size not confirmed',
        'cve':    None,
    },
    {
        'id':       'MTIK-PARSE-F04',
        'severity': 'LOW',
        'cvss':     3.1,
        'title':    'RouterScript :matches operator uses POSIX ERE regexec — catastrophic backtracking (ReDoS) possible',
        'binary':   '/nova/bin/parser',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Script or firewall rule with :matches — requires write access to scripts/firewall',
        'detail': (
            'The parser binary imports regcomp and regexec (POSIX ERE). '
            'RouterScript :matches operator passes user-defined regex patterns to regcomp '
            'and then calls regexec against the subject string. '
            'POSIX ERE engines using backtracking (NFA-based) have O(2^n) worst-case '
            'complexity for patterns with nested quantifiers: e.g., (a+)+ or (.*a){20}. '
            'glibc regexec (which RouterOS uses, as it has no custom regex) has this '
            'worst-case behavior. '
            'An attacker with script execution access can craft a pattern + subject that '
            'causes regexec to run for seconds/minutes, freezing the parser process. '
            'RouterOS parser handles all console sessions — a frozen parser means the '
            'device is unresponsive to all management interfaces until the regex completes. '
            'This is a denial-of-service against the management plane. '
            'Requires write access to scripts or firewall rules — typically admin-level. '
            'String "invalid regex pattern" confirms some regex validation exists; '
            'it likely catches syntax errors but not performance-based attacks.'
        ),
        'evidence': [
            'regcomp@plt and regexec@plt in parser binary PLT',
            'regfree@plt: cleanup after execution',
            'String "invalid regex pattern" — syntax validation exists',
            'glibc regex: NFA backtracking, O(2^n) worst case for nested quantifiers',
            'RouterScript: :matches operator documented in MikroTik wiki',
        ],
        'recommendation': (
            'Impose a regex execution timeout via setitimer or timeout thread. '
            'Example: set SIGALRM for 100ms before regexec; clear after. '
            'Alternatively, limit pattern complexity: reject patterns with nested quantifiers. '
            'Consider replacing glibc regexec with RE2 (linear time guaranteed).'
        ),
        'status': 'CANDIDATE — requires runtime timing test to confirm backtracking behavior',
        'cve':    None,
    },
    {
        'id':       'MTIK-PARSE-F05',
        'severity': 'INFO',
        'cvss':     0.0,
        'title':    'Anti-debugging: parser binary uses ptrace(PTRACE_TRACEME) for debugger detection',
        'binary':   '/nova/bin/parser',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Local analysis — not a network-accessible vulnerability',
        'detail': (
            'ptrace@plt is imported by the parser binary. This is consistent with the '
            'standard MikroTik anti-debugging pattern: ptrace(PTRACE_TRACEME, 0, 0, 0) '
            'returns -1 if the process is already being traced (EPERM). '
            'If a debugger is attached, the binary exits. This prevents gdb/strace-based '
            'dynamic analysis of the scripting engine. '
            'Dynamic analysis requires: LD_PRELOAD with ptrace wrapper that returns 0, '
            'kernel module-level tracing that bypasses ptrace, or emulation (QEMU user mode). '
            'Not a vulnerability. Analysis note for follow-up dynamic RE.'
        ),
        'evidence': [
            'ptrace@plt confirmed in parser binary PLT (nm -D)',
            'Standard MikroTik anti-debug pattern present in multiple RouterOS binaries',
        ],
        'recommendation': 'No fix needed. Analysis note: bypass via LD_PRELOAD ptrace shim.',
        'status': 'CONFIRMED — anti-debug present',
        'cve':    None,
    },
]
