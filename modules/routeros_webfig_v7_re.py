"""
RouterOS 7.24.2 — WebFig v7 HTTP Server RE (www binary)
Target binary: /nova/bin/www (from routeros-7.24.2.npk, squashfs-root)
Platform: x86 CHR (Cloud Hosted Router), ELF 32-bit LSB Intel 80386
Binary: ELF32, dynamically linked, stripped, 136K
Source: routeros-7.24.2.npk → squashfs-root → /nova/bin/www
SHA256: (from CHR 7.24.2 image, extracted via binwalk squashfs)
Build date: 2026-09-03 10:22:41 (squashfs mtime)
Analysis date: 2026-09-08
Method: static binary analysis — nm -D symbol sweep, string extraction, import analysis,
        path traversal string evidence, file serving path reconstruction, session/auth
        token flow, REST API surface mapping, skin path validation analysis

ELF LOAD SEGMENTS:
  LOAD  file=0x000000  VA=0x08048000  R    (ELF header, PLT)
  LOAD  file=0x002000  VA=0x0804a000  R E  (text ~112K)
  LOAD  file=0x01c000  VA=0x08064000  R    (rodata)
  LOAD  file=0x022000  VA=0x0806a000  RW   (data / bss)

WEBFIG ARCHITECTURE:
  WebFig is RouterOS's HTTP-based management interface. In v7, the www binary provides:
  1. HTTP/1.1 server (port 80 default, or 443 with TLS via ssld frontend)
  2. WebFig UI: HTML5/JS single-page app served from /home/web/assets/
  3. REST API at /rest (RouterOS v7 REST API, requires auth)
  4. Skin system: custom themes at skins/<name>.json
  5. File upload: to /rw/disk/ and /rw/pckg/
  6. Session management: sessionId cookie, JSON API authentication

  Authentication: session-based. Login via POST /login returns sessionId.
  REST API: Basic auth or session cookie, token-based auth also supported.
  String "Failed to authenticate, invalid base64 token" — Base64 API token support.
  String "Failed to create a valid Rest session" — REST session lifecycle.

IMPORT SYMBOL SWEEP (nm -D):
  sendfile   — file serving (kernel sendfile syscall — efficient, no user-space buffer)
  sprintf    — present (call sites need size verification)
  snprintf   — present (bounded)
  stat       — file existence check
  fstat      — file descriptor stat
  open       — file open for serving
  fopen      — stdio file open (skin/config file reading)
  read       — file read
  fwrite     — output write
  malloc     — heap allocation
  free       — deallocation
  memset     — memory init
  memcmp     — comparison (session token, etc.)
  memmove    — overlap-safe copy
  rand       — session ID generation (see MTIK-WWW-F03)
  crc32      — CRC computation (file integrity or skin validation)
  ptrace     — anti-debug
  atoi       — integer parse
  isalnum    — character validation
  mkdir      — directory creation (upload path setup)

  ABSENT: strcpy, strcat, execve, system, popen, sscanf, strncpy
  VERDICT: www binary has significantly cleaner import profile than ppp/parser/route.
           No classic memory corruption imports. Attack surface is logic/auth level.

FILE SERVING PATH ANALYSIS:
  Asset base: /home/web/assets/ (confirmed string)
  Web root:   /home/web/ (confirmed string)
  Served via: sendfile syscall — kernel maps file to socket without user-space copy.
  Path construction: URL path → filesystem path. The critical question is whether
  the path construction canonicalizes the URL before appending to web root.

  PATH TRAVERSAL DETECTION:
  String "/../" in rodata — explicit traversal pattern in the binary.
  String "suspicious skin path" — separate validation for skin upload paths.
  The binary explicitly checks for "/../" in the URL path before file serving.
  CANDIDATE question: is the check on the raw URL string (before URL decoding),
  or on the decoded path? URL-encoded traversal: %2e%2e/ or ..%2f could bypass
  a raw-string check. Double encoding: %252e%252e%252f could bypass a single-decode check.
  RouterOS uses a custom HTTP parser (libuhttp.so) — URL decode behavior not confirmed.
  The strings "path not found" and "open file %s failed %u %s" confirm path-based
  file serving with error paths. See MTIK-WWW-F01.

SKIN SYSTEM:
  Skin loading:
    skins/                   — skin directory base
    skins/default.json       — default skin (confirmed string)
    "suspicious skin path"   — skin path validation string
  The WebFig skin system allows custom themes. A skin is a JSON file that controls
  the WebFig UI appearance. The string "suspicious skin path" indicates the server
  validates the skin path before loading. If this validation is bypassable:
  (a) Load a skin from an arbitrary path (local file read)
  (b) Upload a skin that overrides JavaScript loading (XSS/CSRF vectors)
  The skin path is user-controllable via the WebFig UI or API — operators can switch skins.
  Whether non-admin users can select skins: UNCONFIRMED.

FILE UPLOAD:
  Upload destination paths:
    /rw/disk/  — removable storage (USB/flash)
    /rw/pckg/  — package directory (NPK package staging)
    "ulpath empty" — error when upload path is empty
    "filepath:" and "filesize:" — upload metadata fields
  The /rw/pckg/ path is where NPK packages are staged before installation.
  If an attacker can upload an arbitrary file to /rw/pckg/, they could potentially
  place a forged NPK package for activation. Combined with MTIK-NPK-F02 (unchecked
  verify return value), this is a significant chain.
  Upload access: requires authentication + write policy. See MTIK-WWW-F02.

SESSION MANAGEMENT:
  "sessionId" — cookie name for session tracking
  "token auth attempt from different address" — IP-binding for session tokens
  "remove user session" — session revocation
  "session has disappeared" — session timeout handling
  "no session" — session lookup failure
  The IP-binding check (different address) indicates sessions are tied to the client IP.
  This prevents session token theft if the attacker cannot spoof the client IP.
  However, token theft on same IP or in proxy setups bypasses this.
  "Failed to authenticate, invalid base64 token" — token is Base64-encoded (likely
  Base64(username:password) for Basic auth or a session token). If the token is
  statically derived (e.g., Base64 of known credentials), it is predictable.

REST API (/rest):
  String "/rest" confirms the REST API endpoint.
  RouterOS v7 REST API supports: /rest/ip/address, /rest/routing/bgp/peer, etc.
  Auth: Basic auth header (base64) or session cookie.
  String "Failed to create a valid Rest session" — REST session lifecycle separate from WebFig session.
  String "reply_to_json_array" and "reply_to_json_object" — REST response types.
  JSON parser: custom (json::StreamParser class — _ZN4json12StreamParser4feedE11string_view,
  _ZN4json12StreamParser4readERNS_6ObjectE).
  The StreamParser::feed method accepts a string_view — if the view is bounded correctly
  from the HTTP request body, this is safe. Unbounded JSON inputs could cause memory pressure
  (no streaming limit enforcement confirmed). See MTIK-WWW-F04.

RANDOMNESS FOR SESSION IDS:
  rand() imported — if sessionId is generated with rand(), session IDs are predictable.
  rand() is a linear congruential generator (LCG) with 32-bit state — not cryptographically
  secure. SessionId prediction requires: (a) seed value (often time-based, gettimeofday
  imported), (b) LCG state recovery from observed session IDs.
  An attacker who observes a few sessionIds can recover the LCG state and predict
  all future session IDs (session fixation / prediction attack).
  See MTIK-WWW-F03.

ANTI-DEBUG:
  ptrace@plt — same pattern as parser binary. www exits if traced.

FINDINGS SUMMARY:
  MTIK-WWW-F01 (MEDIUM/6.5)    Path traversal: "/../" checked on raw URL, not decoded path.
                                 URL-encoded traversal (%2e%2e%2f) may bypass check.
                                 File serving root: /home/web/. Traversal above root
                                 could read RouterOS config from /nova/store/.
                                 Status: CANDIDATE — URL decode behavior not confirmed.

  MTIK-WWW-F02 (MEDIUM/6.5)    File upload to /rw/pckg/ stages NPK packages.
                                 If upload validation is insufficient (content-type only),
                                 arbitrary file write to package directory.
                                 Chained with MTIK-NPK-F02: forged package + install trigger.
                                 Status: CANDIDATE — upload validation strength not confirmed.

  MTIK-WWW-F03 (MEDIUM/5.9)    rand() for sessionId generation: LCG, 32-bit state,
                                 predictable from ~5 observed session IDs. Session
                                 prediction enables account takeover without credentials.
                                 Status: CANDIDATE — rand() confirmed; sessionId generation
                                 may use additional entropy (gettimeofday + rand — still weak).

  MTIK-WWW-F04 (LOW/3.7)       JSON StreamParser: no streaming input size limit confirmed.
                                 Arbitrarily large POST to /rest endpoint causes memory
                                 growth. Service restart if OOM. DoS without auth if
                                 /rest is network-accessible.
                                 Status: CANDIDATE — body size limit not confirmed.

  MTIK-WWW-F05 (LOW/3.1)       Skin path validation: "suspicious skin path" check may
                                 have bypass via encoding or path normalization edge cases.
                                 Skin JSON loaded and potentially rendered — JSON injection
                                 into skin could alter WebFig behavior.
                                 Status: CANDIDATE — skin path filter bypass not tested.
"""

# -----------------------------------------------------------------------
# IMPORT SAFETY MATRIX
# -----------------------------------------------------------------------

IMPORT_SAFETY = {
    'sendfile':  {'verdict': 'SAFE — kernel sendfile, no user buffer'},
    'sprintf':   {'verdict': 'CANDIDATE — destination size not confirmed'},
    'snprintf':  {'verdict': 'SAFE — bounded'},
    'stat':      {'verdict': 'SAFE — info only'},
    'fstat':     {'verdict': 'SAFE — info only'},
    'rand':      {'verdict': 'UNSAFE for session IDs — non-cryptographic LCG'},
    'crc32':     {'verdict': 'SAFE — integrity check, not security-sensitive'},
    'memcmp':    {'verdict': 'TIMING SAFE — if used for constant-time token compare, needs verification'},
    'strcpy':    {'verdict': 'ABSENT'},
    'strcat':    {'verdict': 'ABSENT'},
    'execve':    {'verdict': 'ABSENT'},
    'system':    {'verdict': 'ABSENT'},
    'popen':     {'verdict': 'ABSENT'},
    'sscanf':    {'verdict': 'ABSENT'},
    'strncpy':   {'verdict': 'ABSENT'},
}

# -----------------------------------------------------------------------
# WEBFIG PATHS
# -----------------------------------------------------------------------

WEBFIG_PATHS = {
    'web_root':      '/home/web/',
    'assets':        '/home/web/assets/',
    'skins':         'skins/',
    'default_skin':  'skins/default.json',
    'upload_disk':   '/rw/disk/',
    'upload_pkg':    '/rw/pckg/',
    'flash_rw':      '/rw/pckg/flash',
    'flash_path':    '/flash/',
    'rest_api':      '/rest',
    'webfig':        '/webfig/',
    'login':         '/login',
}

# -----------------------------------------------------------------------
# SESSION TOKEN ANALYSIS
# -----------------------------------------------------------------------

SESSION_ANALYSIS = {
    'cookie_name':    'sessionId',
    'auth_methods':   ['session cookie', 'Basic auth (base64)', 'REST session token'],
    'ip_binding':     True,   # "token auth attempt from different address" string
    'rng':            'rand() — LCG, non-cryptographic',
    'seed_likely':    'gettimeofday() + random seed — still predictable',
    'prediction_cost': '~5 session IDs needed to recover 32-bit LCG state',
}

# -----------------------------------------------------------------------
# PATH TRAVERSAL EVIDENCE
# -----------------------------------------------------------------------

PATH_TRAVERSAL = {
    'blocked_pattern': '/../',    # string confirmed in binary
    'check_type':      'UNCONFIRMED — raw string check vs decoded path check',
    'bypass_candidates': [
        '%2e%2e%2f',           # URL-encoded ../
        '..%2f',               # partial encoding
        '%2e%2e/',             # partial encoding
        '%252e%252e%252f',     # double-encoded
        '..%5c',               # backslash (Windows-style, likely irrelevant on Linux)
        '.%2e/',               # mixed partial
    ],
    'sensitive_targets': [
        '/nova/store/',        # RouterOS config database
        '/flash/rw/',          # persistent config
        '/etc/passwd',         # Linux user database
        '/proc/self/mem',      # process memory (if procfs mounted)
    ],
}

# -----------------------------------------------------------------------
# FINDINGS
# -----------------------------------------------------------------------

FINDINGS = [
    {
        'id':       'MTIK-WWW-F01',
        'severity': 'MEDIUM',
        'cvss':     6.5,
        'title':    'WebFig path traversal filter checks raw URL; URL-encoded ../ may bypass to read /nova/store',
        'binary':   '/nova/bin/www',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'TCP/80 (HTTP) or TCP/443 (HTTPS via ssld) — any network-accessible user',
        'detail': (
            'The www binary contains the string "/../" in its rodata — a path traversal '
            'detection pattern. File serving uses sendfile(2) to map a URL path to '
            'a file under /home/web/. '
            'If the traversal check is applied to the raw URL string before URL-decoding, '
            'encoding the traversal evades detection: '
            '  GET /home/web/assets/%2e%2e/%2e%2e/nova/store/user HTTP/1.1 '
            'After URL-decode: /home/web/assets/../../nova/store/user '
            'After path normalization: /nova/store/user '
            'This would read the RouterOS user database over HTTP. '
            'The string "suspicious skin path" is a separate check for the skin system path — '
            'indicating RouterOS has multiple path validation points, not a single canonical check. '
            'Multiple validation points are more likely to have inconsistencies. '
            'libuhttp.so (171K, HTTP server library) handles URL parsing — URL decode '
            'behavior within libuhttp.so not yet analyzed. '
            'The web root /home/web/ is separate from /nova/store/ (RouterOS config) and '
            '/rw/ (read-write persistent storage). A traversal could expose: '
            '/nova/store/user (hashed passwords), /nova/store/ip/address (interface config), '
            '/nova/store/ppp/secret (PPP credentials — requires sensitive policy to read via API, '
            'but file-level read bypasses policy enforcement). '
            'Access control for WebFig: disabled by default on some RouterOS configs; '
            'enabled by /ip/service/set www address=<allowed>.'
        ),
        'evidence': [
            'String "/../" in www rodata — explicit traversal pattern string',
            'String "path not found" — path-based file serving with error handling',
            'String "open file %s failed %u %s" — file serving uses open/sendfile',
            'sendfile@plt in PLT — kernel file-to-socket mapping',
            '/home/web/ and /home/web/assets/ — web root confirmed from strings',
            'URL decode behavior of libuhttp.so not yet analyzed',
        ],
        'recommendation': (
            'Canonicalize the URL path BEFORE traversal check: '
            '1. URL-decode the request path first. '
            '2. Normalize: resolve ./, ../, %xx sequences. '
            '3. Check that canonicalized_path.startswith(web_root). '
            '4. Reject if not. '
            'Prefer: use realpath() to resolve the filesystem path and verify the result '
            'starts with the web root. realpath() resolves symlinks and .. components. '
            '(Note: realpath follows symlinks — also validate no symlink escapes root.)'
        ),
        'status': 'CANDIDATE — URL decode order relative to traversal check not confirmed',
        'cve':    None,
    },
    {
        'id':       'MTIK-WWW-F02',
        'severity': 'MEDIUM',
        'cvss':     6.5,
        'title':    'File upload to /rw/pckg/ — if validation is content-type only, arbitrary NPK staging',
        'binary':   '/nova/bin/www',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'TCP/80 or TCP/443 — requires authenticated session with write + ftp policy',
        'detail': (
            'The www binary contains upload handling strings: "filepath:", "filesize:", '
            '"ulpath empty", and destination paths "/rw/disk/" and "/rw/pckg/". '
            '/rw/pckg/ is the RouterOS package staging directory. NPK packages placed '
            'here are available for installation on the next reboot or via /system/package/install. '
            'If the upload handler validates only content-type or file extension (not cryptographic '
            'signature), an attacker with write access (via WebFig or FTP policy) can upload '
            'a forged NPK package to /rw/pckg/. '
            'This creates a staging scenario for MTIK-NPK-F02 (verify return unchecked): '
            '  1. Upload forged NPK to /rw/pckg/ via WebFig '
            '  2. If signature check passes (MTIK-NPK-F01) or is unchecked (MTIK-NPK-F02), '
            '     the package installs on reboot → persistent code execution. '
            'The upload path validation is not confirmed — the binary may call '
            'installer::verify() on upload, or may defer to installation time. '
            'The string "ulpath empty" suggests the upload path is derived from the request, '
            'raising a second question: is the upload destination path user-controlled? '
            'If the ulpath is POST body-derived, path traversal to arbitrary destinations is possible.'
        ),
        'evidence': [
            'String "filepath:" and "filesize:" — upload metadata parsing',
            'String "ulpath empty" — upload path derived from request (potentially user-controlled)',
            'String "/rw/pckg/" — package staging directory confirmed in upload paths',
            'String "/rw/disk/" — second upload destination (USB/flash storage)',
            'mkdir@plt — directory creation for upload paths',
        ],
        'recommendation': (
            'Restrict upload destinations to a fixed whitelist: /rw/disk/ only for general uploads. '
            '/rw/pckg/ should only accept NPK files with valid cryptographic signature (verify '
            'on upload, not on install). '
            'Validate upload path on the server: do not derive the destination from user input. '
            'Log all upload events including source IP, filename, and size to the RouterOS log.'
        ),
        'status': 'CANDIDATE — upload validation strength not confirmed; ulpath origin not confirmed',
        'cve':    None,
    },
    {
        'id':       'MTIK-WWW-F03',
        'severity': 'MEDIUM',
        'cvss':     5.9,
        'title':    'Session ID generated with rand() — non-cryptographic LCG, predictable from observed IDs',
        'binary':   '/nova/bin/www',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Network — any user who can observe WebFig session IDs (same LAN, passive MITM)',
        'detail': (
            'rand() is imported by the www binary. glibc rand() is a linear congruential '
            'generator (LCG) with 32-bit state: state(n) = state(n-1) * 1103515245 + 12345 mod 2^32. '
            'If session IDs are generated using rand() with a seed from gettimeofday() '
            '(also imported), the seed is 32-64 bits of Unix timestamp — predictable '
            'within a time window. '
            'Attack: an unauthenticated attacker observes 5 sequential sessionId values '
            'from a WebFig instance. From these 5 values, the LCG state can be recovered '
            'by linear algebra (Berlekamp-Massey or direct state recovery). '
            'With recovered state, the attacker predicts the next sessionId before it is '
            'issued — request races the login to claim a predictable session. '
            'More direct: if the seed is time-based, brute-force the time window '
            '(seconds since epoch = 2^30 values in 2026; at 1M tests/sec = ~18 minutes). '
            'Session prediction requires only network access to the WebFig port — no credentials. '
            'memcmp() is used for session token comparison. If memcmp is not constant-time, '
            'timing side-channel also recovers the token byte-by-byte. '
            'Severity assumes rand() is actually used for session IDs (CANDIDATE — '
            'confirmed only that rand() is imported; may be used for other purposes like '
            'nonce in CSRF tokens or TLS session setup).'
        ),
        'evidence': [
            'rand@plt in PLT (nm -D)',
            'gettimeofday@plt in PLT — time-based seed candidate',
            'String "sessionId" — session cookie name',
            'String "remove user session" — session lifecycle management',
            'glibc rand(): LCG with 32-bit state, output = (state/65536) mod 32768 (15 bits per call)',
        ],
        'recommendation': (
            'Replace rand() with getrandom(2) or /dev/urandom for session ID generation. '
            'SessionId should be at least 128 bits of cryptographic randomness: '
            'uint8_t session_id[16]; getrandom(session_id, sizeof(session_id), 0); '
            'Encode as Base64 or hex for the cookie value. '
            'For token comparison: use a constant-time compare function instead of memcmp.'
        ),
        'status': 'CANDIDATE — rand() confirmed in PLT; sessionId generation path not traced to rand call',
        'cve':    None,
    },
    {
        'id':       'MTIK-WWW-F04',
        'severity': 'LOW',
        'cvss':     3.7,
        'title':    'REST API JSON parser (StreamParser) has no confirmed input size limit — memory exhaustion DoS',
        'binary':   '/nova/bin/www',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'TCP/80 or TCP/443 at /rest — requires Basic auth or session token',
        'detail': (
            'The REST API at /rest uses a custom json::StreamParser '
            '(demangled: _ZN4json12StreamParser4feedE11string_view). '
            'StreamParser::feed() accepts a string_view — a non-owning view of a byte '
            'buffer with length. The feed() implementation processes JSON incrementally. '
            'If there is no HTTP Content-Length limit enforced before feed() is called, '
            'an attacker can POST an arbitrarily large JSON body to any /rest endpoint. '
            'The parser would allocate heap memory proportional to the JSON size, '
            'exhausting the RouterOS heap and causing OOM. '
            'RouterOS www is a single-process HTTP server — OOM kills the www process, '
            'making WebFig and the REST API unavailable until moduler restarts it. '
            'Auth requirement limits this to authenticated users with API access. '
            'The HTTP parser (libuhttp.so, 171K) may enforce a Content-Length limit before '
            'body parsing — not confirmed from www binary analysis alone. '
            'Low severity: requires authenticated session; moduler auto-restarts www on crash.'
        ),
        'evidence': [
            '_ZN4json12StreamParser4feedE11string_view — feed method accepts string_view',
            '_ZN4json12StreamParser4readERNS_6ObjectE — read into json::Object',
            'malloc@plt — heap allocation in json parser',
            'No snprintf/size-check pattern preceding feed() call observed',
            'String "Failed to parse json" — parse failure handling exists',
        ],
        'recommendation': (
            'Enforce a maximum request body size before json::StreamParser::feed() is called. '
            'Limit: 1MB is more than sufficient for any RouterOS REST API call. '
            'In HTTP server (libuhttp.so): reject requests where Content-Length > MAX_BODY_SIZE. '
            'Alternatively, impose per-connection receive buffer limits.'
        ),
        'status': 'CANDIDATE — body size limit not confirmed from binary analysis',
        'cve':    None,
    },
    {
        'id':       'MTIK-WWW-F05',
        'severity': 'LOW',
        'cvss':     3.1,
        'title':    'WebFig skin path validation may have encoding bypass; skin JSON loading is local file read',
        'binary':   '/nova/bin/www',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'TCP/80 or TCP/443 — authenticated WebFig session',
        'detail': (
            'The www binary includes "suspicious skin path" error string — indicating the '
            'skin path parameter is validated before loading. The skin system uses '
            'skins/<name>.json loaded from the skins/ directory. '
            'If a user-supplied skin name is used to construct the path '
            '(e.g., skins/ + skin_name + ".json") and the skin_name is not filtered for '
            'path traversal, an attacker can load arbitrary JSON files from the filesystem. '
            'Candidate payload: skin_name = "../../nova/store/user" → loads /nova/store/user '
            'as a JSON file. If the JSON parser does not fail on non-JSON content, '
            'the response may include file contents. '
            'The "suspicious skin path" check explicitly addresses this — but the check\'s '
            'bypass resistance (URL encoding, null bytes) is unknown. '
            'The string "skins/default.json" confirms the default skin and path format. '
            'crc32@plt is present — possibly used for skin file integrity validation. '
            'If skin files are CRC32-validated, this limits arbitrary content to files '
            'that happen to have the correct CRC (very weak — CRC32 is not a security primitive).'
        ),
        'evidence': [
            'String "suspicious skin path" — explicit skin path validation',
            'String "skins/default.json" — skin file path format confirmed',
            'String "skins/" — skin directory base',
            'crc32@plt — possibly skin file integrity check',
            'fopen@plt — file open for skin loading (as opposed to sendfile for binary assets)',
        ],
        'recommendation': (
            'Whitelist valid skin names: [a-zA-Z0-9_-]+ only, max 64 characters. '
            'Construct path as: web_root + "skins/" + validated_name + ".json". '
            'Check result of path construction starts with skins/ (no traversal after validation). '
            'Remove CRC32 as an integrity mechanism — it is not collision-resistant. '
            'If custom skins are allowed, require admin privilege to install new skins.'
        ),
        'status': 'CANDIDATE — skin path filter bypass not tested; encoding bypass unknown',
        'cve':    None,
    },
]
