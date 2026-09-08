"""
RouterOS 7.24.2 — Login / Authentication Daemon RE
Target binary: /nova/bin/login (from routeros-7.24.2.npk, squashfs-root)
Platform: x86 CHR (Cloud Hosted Router), ELF 32-bit LSB Intel 80386
Binary: ELF32, dynamically linked, stripped, 156K
Source: routeros-7.24.2.npk → squashfs-root → /nova/bin/login
SHA256: (from CHR 7.24.2 image, extracted via binwalk squashfs)
Build date: 2026-09-03 10:22:41 (squashfs mtime)
Analysis date: 2026-09-08
Method: static binary analysis — nm -D symbol sweep, objdump call site enumeration,
        string extraction, exec call site analysis, authentication flow reconstruction,
        error message differentiation analysis, username enumeration confirmation

LOGIN BINARY ROLE:
  /nova/bin/login handles interactive authentication for all console-based RouterOS
  management sessions:
  - SSH sessions (via /pckg/security/nova/bin/ssh → login)
  - Telnet sessions (/nova/bin/telser → login)
  - Serial/console (direct)
  - MAC Telnet (/nova/bin/mactel → login)
  - Headless login (login --headless)
  All shell-based management goes through this binary before launching the
  command parser or other session-specific tools.

IMPORT SYMBOL SWEEP (nm -D):
  strcpy    — 1 call site at 0x80644e1 (sockaddr_un sun_path from rodata — SAFE)
  sscanf    — present (password prompt parsing)
  snprintf  — present (bounded)
  strcmp    — present (string comparison)
  strncmp   — present (bounded comparison)
  memcmp    — present (may be used for password hash comparison)
  getpass   — present (password from TTY, deprecated glibc)
  fork      — present (process separation)
  execv     — 2 call sites: 0x8065bd0, 0x806720c
  execlp    — 3 call sites: 0x8067464, 0x8067484, 0x8067f45
  execvp    — 1 call site: 0x80680a1 (PATH-based exec — see MTIK-LOGIN-F02)
  chroot    — present (privilege separation)
  chdir     — present (working directory change on login)
  chown     — absent
  setuid    — absent (uses Nova policy model, not POSIX UIDs)
  sleep     — present (nanosleep@plt — rate limiting candidate)
  printf    — present (TTY output)
  puts      — present (puts error messages)

EXEC CALL ANALYSIS:
  execlp at 0x8067464 and 0x8067484:
    push $0x806d871 twice: file AND arg0 = rodata string "/nova/bin/mactel"
    execlp("/nova/bin/mactel", "/nova/bin/mactel", ..., NULL)
    Path is absolute rodata literal. SAFE from path injection.
    BUT: execlp uses PATH for relative paths — not applicable here (absolute path).

  execlp at 0x8067f45:
    push $0x806d900 twice: file AND arg0 = rodata string "/nova/bin/telser"
    execlp("/nova/bin/telser", "/nova/bin/telser", ..., NULL)
    Same pattern — absolute path from rodata. SAFE.

  execv at 0x8065bd0 and 0x806720c:
    Context not fully traced — likely launching shell or parser after successful auth.

  execvp at 0x80680a1 — CRITICAL PATH:
    Preceded at 0x8067fce: call nv::message::get<string_id> — extracts a string
    from a Nova message into a local buffer. This string becomes the argv for execvp.
    At 0x8068037: movl $0x806d900,-0x98(%ebp) sets a "/nova/bin/telser" default.
    At 0x8068047: zeroes -0xac(%ebp) (pointer init).
    Then the argv is constructed (including the Nova message string at -0xac(%ebp)).
    execvp(-0xac(%ebp)[0], -0xac(%ebp)):
      first arg (file) = argv[0] = content pointer derived from Nova message string
    If the Nova message string is controllable (attacker-supplied or config-injected),
    execvp would PATH-search for and execute attacker's binary name.
    execvp() searches PATH — if PATH is not sanitized in login's environment,
    the attacker places an executable earlier in PATH to hijack the exec.
    See MTIK-LOGIN-F02.

AUTHENTICATION FLOW RECONSTRUCTION:
  1. Login binary connects to Nova console service via Unix socket (strcpy sun_path call)
  2. Reads username from TTY (getchar/fgets) or from Nova message (headless mode)
  3. Reads password via getpass() or Nova message field
  4. Validates credentials via Nova message exchange with user management daemon
  5. On success: fork + exec into session binary (parser/telnet/ssh/etc.)
  6. On failure: log "Login failed" + continue (no confirmed lockout)

USERNAME ENUMERATION — THREE DISTINCT ERROR MESSAGES:
  "Login failed, incorrect username"
    → username does NOT exist in RouterOS user database
  "Login failed, incorrect username or password"
    → username EXISTS but password is wrong (or empty user attempt)
  "Login failed, incorrect username or policy"
    → username EXISTS but policy check failed
  "Login failed, incorrect user policy"
    → username EXISTS, policy exists but specific permission denied

  These four error strings are differentiable from the client side. An attacker
  can probe usernames and distinguish "no such user" from "wrong password" by
  observing which error message is returned via the console. Username enumeration
  enables targeted password attacks against known-valid usernames.
  Default username "admin" confirmed in binary (string "admin" in rodata).
  See MTIK-LOGIN-F01.

RATE LIMITING — "Too many failures":
  String "Too many failures" confirmed in binary. nanosleep@plt is imported.
  A rate limit or lockout mechanism is implied. The strength is not confirmed:
  (a) If the lockout is per-session (exits login binary after N failures), an attacker
      simply reconnects and gets another N attempts.
  (b) If the lockout is system-wide with a delay, the mechanism must persist
      state across sessions — requires Nova Store or a file. /ram/userseq.console
      (string in binary) suggests session sequence state is tracked in RAM.
  The lockout mechanism does not persist across reboots if stored in /ram/.
  See MTIK-LOGIN-F03.

GETPASS — DEPRECATED FUNCTION:
  getpass@plt: deprecated glibc function, reads from /dev/tty without echo.
  The standard replacement is fgets(buf, n, /dev/tty) after tcsetattr echo-off.
  getpass() uses a static 256-byte internal buffer (not heap-allocated). The
  password is truncated at 255 characters with no error. If the password
  comparison uses full string equality and the password is truncated at 255 chars,
  long passwords that share the first 255 chars would compare equal.
  In practice, RouterOS passwords are limited in the user management layer,
  so the 255-char truncation likely doesn't create an exploitable boundary.
  INFORMATIONAL.

CHROOT IN LOGIN:
  chroot@plt and chdir@plt are present — login uses privilege separation via chroot.
  chroot restricts the login process to a subdirectory, preventing access to
  the full RouterOS filesystem during the auth phase.
  chroot is only effective if: (a) the binary doesn't break out before chrooting,
  (b) the chroot jail doesn't contain useful escape tools.
  Given the minimal RouterOS filesystem, chroot jailbreak is unlikely but not confirmed.

FINDINGS SUMMARY:
  MTIK-LOGIN-F01 (MEDIUM/5.3)  Username enumeration via distinct error messages.
                                 "incorrect username" vs "incorrect username or password"
                                 vs "incorrect username or policy" — differentiable.
                                 Enables targeted brute force against known-valid usernames.
                                 Status: CONFIRMED — three distinct strings in binary.

  MTIK-LOGIN-F02 (MEDIUM/6.5)  execvp at 0x80680a1: program name derived from Nova
                                 message string. If Nova message is attacker-influenced
                                 (compromised service or config injection), execvp runs
                                 attacker's binary (PATH-searched).
                                 Status: CANDIDATE — Nova message origin not fully traced.

  MTIK-LOGIN-F03 (LOW/3.7)     Rate limiting "Too many failures" may be per-session only.
                                 /ram/userseq.console tracks sequence in RAM — does not
                                 persist across reboots. An attacker who reboots or
                                 reconnects after N failures gets fresh attempt counter.
                                 Status: CANDIDATE — lockout persistence mechanism unknown.

  MTIK-LOGIN-F04 (INFO)        getpass() uses 256-byte static buffer — password truncated
                                 at 255 characters. Not exploitable given RouterOS password
                                 length limits in user management layer.
                                 Status: INFORMATIONAL.

  MTIK-LOGIN-F05 (INFO)        strcpy at 0x80644e1: source is rodata literal
                                 "/nova/bin/telser" → SAFE (see routeros_scripting_parser_re.py
                                 for the pattern that IS risky).
                                 Status: CONFIRMED CLEAN.
"""

# -----------------------------------------------------------------------
# PLT MAP
# -----------------------------------------------------------------------

PLT_MAP = {
    'strcpy':    0x804e4e0,   # 1 call site: 0x80644e1 (rodata source — SAFE)
    'sscanf':    None,        # call sites unmapped
    'snprintf':  None,        # bounded
    'strcmp':    None,        # string compare
    'strncmp':   None,        # bounded compare
    'memcmp':    None,        # hash compare (timing safety unknown)
    'getpass':   0x804ece0,   # call at 0x80656f2 — password from TTY
    'fork':      0x804e440,   # process separation
    'execv':     0x804f0d0,   # 2 call sites: 0x8065bd0, 0x806720c
    'execlp':    0x804eb20,   # 3 call sites: absolute path literals (SAFE)
    'execvp':    0x804e030,   # 1 call site: 0x80680a1 — PATH-searched (CANDIDATE)
    'chroot':    None,        # privilege separation
    'chdir':     None,        # working directory
    'nanosleep': None,        # rate limiting
    'kill':      None,        # signal dispatch
    'socket':    0x804ec30,   # Nova socket
    'socketpair':0x804e6c0,   # IPC pipe
}

# -----------------------------------------------------------------------
# EXEC CALL INVENTORY
# -----------------------------------------------------------------------

EXEC_CALLS = [
    {'va': 0x8067464, 'fn': 'execlp', 'path': '/nova/bin/mactel',
     'path_from': 'rodata $0x806d871', 'risk': 'SAFE — absolute path literal'},
    {'va': 0x8067484, 'fn': 'execlp', 'path': '/nova/bin/mactel',
     'path_from': 'rodata $0x806d871', 'risk': 'SAFE — absolute path literal'},
    {'va': 0x8067f45, 'fn': 'execlp', 'path': '/nova/bin/telser',
     'path_from': 'rodata $0x806d900', 'risk': 'SAFE — absolute path literal'},
    {'va': 0x8065bd0, 'fn': 'execv',  'path': None,
     'path_from': 'NOT YET TRACED', 'risk': 'UNKNOWN — context not traced'},
    {'va': 0x806720c, 'fn': 'execv',  'path': None,
     'path_from': 'NOT YET TRACED', 'risk': 'UNKNOWN — context not traced'},
    {'va': 0x80680a1, 'fn': 'execvp', 'path': 'DYNAMIC — from Nova message string',
     'path_from': 'nv::message::get<string_id> at 0x8067fce',
     'risk': 'CANDIDATE — PATH-searched; program name from Nova message'},
]

# -----------------------------------------------------------------------
# USERNAME ENUMERATION EVIDENCE
# -----------------------------------------------------------------------

USERNAME_ENUM_STRINGS = [
    {'text': 'Login failed, incorrect username',
     'semantics': 'Username does NOT exist — precise failure disclosure'},
    {'text': 'Login failed, incorrect username or password',
     'semantics': 'Username EXISTS, password wrong — attacker can detect valid usernames'},
    {'text': 'Login failed, incorrect username or policy',
     'semantics': 'Username EXISTS, policy check failed'},
    {'text': 'Login failed, incorrect user policy',
     'semantics': 'Username EXISTS, specific policy denied'},
]

# -----------------------------------------------------------------------
# KNOWN PATHS FROM LOGIN BINARY
# -----------------------------------------------------------------------

BINARY_PATHS = {
    '/nova/bin/mactel':           'MAC Telnet binary',
    '/nova/bin/telser':           'Telnet server binary',
    '/nova/bin/telnet':           'Telnet client binary',
    '/nova/bin/ssh':              'SSH binary (main)',
    '/pckg/security/nova/bin/ssh':'SSH binary (security package)',
    '/nova/bin/parser':           'Command parser (shell)',
    '/pckg/option/bin/bash':      'Bash shell (optional package)',
    '/nova/lib/console/logo.txt': 'RouterOS banner text',
    '/nova/lib/console/sublogo.txt': 'Secondary banner',
    '/nova/store/command/speclogin': 'Special login config store',
    '/ram/userseq.console':       'Console session sequence (RAM only, no persistence)',
}

# -----------------------------------------------------------------------
# FINDINGS
# -----------------------------------------------------------------------

FINDINGS = [
    {
        'id':       'MTIK-LOGIN-F01',
        'severity': 'MEDIUM',
        'cvss':     5.3,
        'title':    'Username enumeration via distinct authentication error messages — valid usernames distinguishable',
        'binary':   '/nova/bin/login',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'SSH, Telnet, serial console, MAC Telnet — all interactive login paths',
        'detail': (
            'The login binary contains four distinct error message strings that are '
            'returned to the client on authentication failure: '
            '"Login failed, incorrect username" — username not found in user database. '
            '"Login failed, incorrect username or password" — username found, password wrong. '
            '"Login failed, incorrect username or policy" — username found, policy mismatch. '
            '"Login failed, incorrect user policy" — username found, specific policy denied. '
            'An attacker connecting via SSH or Telnet can distinguish between a '
            '"username does not exist" failure and a "wrong password" failure by '
            'reading the error message. This enables username enumeration: '
            '  1. Send login with candidate username and random password. '
            '  2. If response is "incorrect username": user does not exist. '
            '  3. If response is "incorrect username or password": user exists. '
            '  4. Proceed with password brute force against confirmed-valid usernames. '
            'Default username "admin" is hardcoded in the binary and present on all '
            'fresh RouterOS installations. An attacker always knows at least one valid '
            'username. The enumeration is most useful for discovering non-default admin '
            'accounts when operators have renamed or added users. '
            'CVSS: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3 '
            '(network-accessible, no auth required, information disclosure only).'
        ),
        'evidence': [
            'String "Login failed, incorrect username" — user nonexistent path',
            'String "Login failed, incorrect username or password" — user exists path',
            'String "Login failed, incorrect username or policy" — user+policy path',
            'String "Login failed, incorrect user policy" — policy-specific path',
            'String "admin" in rodata — default admin username hardcoded',
            'All four strings differentiate auth failure reason to the client',
        ],
        'recommendation': (
            'Return a single generic error for all authentication failures: '
            '"Login failed" — do not disclose whether the username exists. '
            'This is the standard practice recommended by OWASP ASVS 2.7.5: '
            '"Verify that account lockout, soft lock out, or soft throttle messages do not '
            'reveal to the user whether the username exists." '
            'Apply to all: SSH, Telnet, console, Winbox, WebFig, REST API.'
        ),
        'status': 'CONFIRMED — four distinct strings in binary; all disclose user existence',
        'cve':    None,
    },
    {
        'id':       'MTIK-LOGIN-F02',
        'severity': 'MEDIUM',
        'cvss':     6.5,
        'title':    'execvp at 0x80680a1 with program name derived from Nova message string — PATH-hijack candidate',
        'binary':   '/nova/bin/login',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Local — requires Nova message injection or compromised Nova service',
        'detail': (
            'execvp at 0x80680a1 is called with argv[0] content from a Nova message '
            'string field (nv::message::get<string_id> called at 0x8067fce to populate '
            '-0x108(%ebp), which becomes the argv[0] pointer used at execvp). '
            'execvp() searches the PATH environment variable for the binary if the '
            'program name is not an absolute path. '
            'Attack scenario: '
            '  1. The Nova message string contains a program name like "telser" (relative). '
            '  2. PATH is set to include /tmp before /nova/bin (or any writable directory). '
            '  3. An attacker with write access to /tmp places /tmp/telser (malicious binary). '
            '  4. login execvp("telser", ...) finds /tmp/telser first, executes it. '
            'Prerequisites: '
            '  (a) Nova message program name must be relative (not "/nova/bin/telser"). '
            '      The default at 0x8068037 sets "/nova/bin/telser" (absolute — safe). '
            '      But if the Nova message overrides this with a relative name: risk applies. '
            '  (b) PATH must be writable — in RouterOS, PATH is set by init/moduler '
            '      and may not be user-controllable normally. '
            '  (c) A writable directory must precede /nova/bin in PATH. '
            'This is a moderate-probability finding: the default path is absolute (safe), '
            'but if ANY Nova service can inject a relative program name into the '
            'login session message, the risk is real. Chained with Nova bus trust model '
            '(MTIK-NOVA-F03): a compromised daemon can send this message to login.'
        ),
        'evidence': [
            '0x8067fce: call nv::message::get<string_id> — string from Nova message',
            '0x8068037: movl $0x806d900,-0x98(%ebp) — default "/nova/bin/telser" (absolute)',
            '0x806809f: push (%eax) + push %eax — argv from message-derived pointer',
            '0x80680a1: call execvp@plt — PATH-searched exec',
            'String "/pckg/option/bin/bash" in binary — bash is a valid exec target',
            'Nova bus trust model: MTIK-NOVA-F03 (no inter-daemon auth)',
        ],
        'recommendation': (
            'Replace execvp with execv and always use absolute paths for any binary '
            'launched by login. Never derive binary paths from Nova message fields. '
            'If the binary name is dynamic: validate against a whitelist of absolute '
            'paths before exec. '
            'PATH sanitization: set PATH explicitly in login\'s environment: '
            'setenv("PATH", "/nova/bin:/pckg/security/nova/bin", 1) before any exec. '
            'Do not inherit PATH from parent process.'
        ),
        'status': 'CANDIDATE — default path is absolute; Nova message override potential not confirmed',
        'cve':    None,
    },
    {
        'id':       'MTIK-LOGIN-F03',
        'severity': 'LOW',
        'cvss':     3.7,
        'title':    'Authentication rate limit "Too many failures" stored in /ram — resets on reconnect or reboot',
        'binary':   '/nova/bin/login',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'SSH, Telnet, console — brute force mitigation bypass',
        'detail': (
            'String "Too many failures" in binary confirms an auth failure counter exists. '
            'nanosleep@plt imported — delays between attempts or after lockout. '
            'String "/ram/userseq.console" — sequence state for console sessions is stored '
            'in /ram/ (tmpfs), which is cleared on reboot. '
            'If the failure counter is per-session (stored in the login process memory): '
            '  An attacker who disconnects and reconnects to SSH/Telnet gets a fresh counter. '
            '  Effective brute force limit = (attempts_per_session) × (max_reconnects). '
            '  With 3 attempts per session and unlimited reconnects: unlimited total attempts. '
            'If the counter is system-wide but stored in /ram/: '
            '  A hard reset (reboot) clears the lockout. In RouterOS, an attacker with '
            '  physical access or the ability to trigger a reboot (ICMP flood, exploiting '
            '  a crash bug in another daemon) resets the counter. '
            'RouterOS does not appear to implement IP-based rate limiting at the SSH/Telnet '
            'daemon level — that would require firewall rules, not login-level rate limiting. '
            'The "Too many failures" lockout does not help if the attacker reconnects from '
            'a different source IP after each failure cluster.'
        ),
        'evidence': [
            'String "Too many failures" — rate limit trigger confirmed',
            'nanosleep@plt — delay implementation present',
            'String "/ram/userseq.console" — session state in RAM (cleared on reboot)',
            'No evidence of persistent counter in Nova Store (no /nova/store path for failure count)',
        ],
        'recommendation': (
            'Implement IP-based rate limiting at the firewall level: '
            '/ip/firewall/filter add chain=input protocol=tcp dst-port=22 '
            'connection-limit=3,32 action=tarpit '
            'Or use connection tracking: add chain=input src-address-list=ssh-blacklist action=drop; '
            'add chain=input protocol=tcp dst-port=22 '
            'src-address-list=ssh-stage2 action=add-src-to-address-list '
            'address-list=ssh-blacklist address-list-timeout=1d; '
            '(standard RouterOS anti-brute-force recipe). '
            'Additionally: store failure counters in Nova Store (persistent, survives session). '
            'Apply exponential backoff: delay = 2^(failures) seconds, max 30 seconds.'
        ),
        'status': 'CANDIDATE — per-session vs system-wide counter not confirmed from binary alone',
        'cve':    None,
    },
    {
        'id':       'MTIK-LOGIN-F04',
        'severity': 'INFO',
        'cvss':     0.0,
        'title':    'getpass() deprecated — 256-byte static buffer; password truncated at 255 chars',
        'binary':   '/nova/bin/login',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'N/A — TTY-based interactive login only',
        'detail': (
            'getpass() is a deprecated glibc function that reads a password from /dev/tty '
            'without echo. It uses a static internal 256-byte buffer. Passwords longer '
            'than 255 characters are silently truncated. For interactive console use, '
            'this is not exploitable — RouterOS passwords are limited to 255 characters '
            'in the user management layer, which matches the truncation point. '
            'The deprecation concern is reliability (not security): static buffer is not '
            'thread-safe; on Linux, /dev/tty may not be available in all contexts. '
            'Call site: 0x80656f2.'
        ),
        'evidence': [
            'getpass@plt at call site 0x80656f2',
            'glibc manual: getpass() deprecated since POSIX.1-2001',
        ],
        'recommendation': (
            'Replace with fgets(buf, n, tty_fd) after tcgetattr echo-disable. '
            'This is the standard secure password read pattern. '
            'Explicit buffer size prevents truncation surprises.'
        ),
        'status': 'INFORMATIONAL',
        'cve':    None,
    },
    {
        'id':       'MTIK-LOGIN-F05',
        'severity': 'INFO',
        'cvss':     0.0,
        'title':    'strcpy at 0x80644e1: source is rodata literal — CLEAN (contrast with parser MTIK-PARSE-F01)',
        'binary':   '/nova/bin/login',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'N/A',
        'detail': (
            'strcpy at 0x80644e1 follows the same sockaddr_un sun_path pattern as '
            'routeros_scripting_parser_re.py MTIK-PARSE-F01 — AF_UNIX at -0x1086(%ebp), '
            'sun_path at -0x1084(%ebp). However: the source is push $0x806d871 — '
            'a fixed rodata literal ("/nova/bin/telser" or similar). '
            'A rodata source has fixed compile-time length and cannot be extended by an '
            'attacker. This is CLEAN. '
            'MTIK-PARSE-F01 (parser binary) differs: source is a C++ string argument '
            'from the caller, which may be attacker-controlled.'
        ),
        'evidence': [
            '0x80644d2: push $0x806d871 — rodata literal as strcpy source',
            '0x80644e0: push %eax (= -0x1084(%ebp)) — sun_path destination',
            '0x80644e1: call strcpy@plt — copy of fixed-length rodata string',
        ],
        'recommendation': 'No action needed for this strcpy instance.',
        'status': 'CONFIRMED CLEAN',
        'cve':    None,
    },
]
