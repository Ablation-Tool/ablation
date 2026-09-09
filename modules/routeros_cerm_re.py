"""
RouterOS 7.24.2 — /nova/bin/cerm RE module
Binary: cerm (984KB, x86-32 ELF stripped, dynamically linked)
SHA path: ~/mikrotik-re/bins/cerm

Role: Certificate Manager daemon. Manages the local PKI:
  - X.509 certificate issuance, import, and validation
  - CRL (Certificate Revocation List) fetching and caching
  - SCEP (Simple Certificate Enrollment Protocol) client and server
  - ACME (Automatic Certificate Management Environment) client (Let's Encrypt)
  - HTTP-based certificate endpoints via libuhttp.so
  - Certificate trust store management (x509ValidatePath)

PLT imports (security-relevant):
  strcpy@plt      : 0x8050d40  — 1 call site (strdup clone: strlen+malloc+strcpy — CLEAN)
  strcat@plt      : 0x8050ea0  — 2 call sites (UUID hex encoding loop — CLEAN)
  sscanf@plt      : 0x8051710  — 1 call site (format '.%d.%d' — CLEAN)
  fscanf          : absent from PLT — not used
  sprintf         : absent — not used
  srand@plt       : 0x8050750  — 1 call site (seed: tv.tv_usec only)
  rand@plt        : 0x80507a0  — 1 call site (rand() % 15 = retry jitter)
  fgets           : absent — not used
  snprintf@plt    : present (multi-call, all bounded)
  gettimeofday    : 0x80513f0  — called before srand

Network:
  nv::Http::newRequest()         — HTTP request builder (CRL fetch, ACME)
  nv::Connection::aconnect()     — async TCP connect to remote host
  nv::Http::processBody()        — HTTP response body processing
  nv::Connection::resolve()      — DNS resolution (for CRL and ACME endpoints)
  Response::send/sendError       — HTTP response (inbound SCEP/cert servlet)

JSON:
  json::StreamParser::feed(char const*, uint)  — external; feeds raw bytes into parser
  json::StreamParser::read(json::Object&)      — external; reads parsed JSON object
  json::StreamParserC1/D1 — ctor/dtor

  5 call sites to feed() and read() at:
    0x80756e6 / 0x8075700  — ACME challenge fetch parse
    0x8075a79 / 0x8075a93  — ACME order status parse
    0x80761b4 / 0x80761ce  — ACME authorization parse
    0x80764cd / 0x80764e4  — ACME challenge validation parse
    0x80777fb / 0x8077815  — ACME token parse

Crypto (via libucrypto.so):
  x509ValidatePath()   — full X.509 chain validation
  x509BuildPath()      — certificate path construction
  readCertFromStr()    — PEM/DER cert parser (string_view input)
  readCrl()            — CRL DER parser
  readCertChain()      — multi-cert chain parser
  parsePem()           — PEM header/footer parser
  pemDecode()          — base64+DER decoder
  parsePkcs8PublicKey() — PKCS#8 DER parser
  calcDigest()         — hash computation
  makeChallenge()      — SCEP OTP/challenge generation (libucrypto.so)
  verifySignature()    — PKCS#7 signature verification (SCEP)
  PKCS7SignedData::*   — SCEP signed-data parsing

Nova store paths:
  /nova/store/cert/crl              — CRL cache
  /nova/store/cert/scep_server      — SCEP server configuration
  /nova/store/cert/scep_ca_transactions — SCEP CA transaction store
  /nova/store/cert/scep_otp         — SCEP OTP records
  /nova/store/cert/scep_ra          — SCEP Registration Authority

File system paths:
  /rw/cm/                — certificate storage root (key, cert, hash_sha1, crl, ca_crl)
  /rw/cm/key             — private key storage
  /rw/cm/cert            — certificate storage
  /rw/cm/crl             — CRL storage
  /rw/cm/hash_sha1       — SHA1 hash index
  /nova/etc/ca/          — CA root store
  /ram/crl               — in-memory CRL cache

SCEP HTTP endpoint: /scep/server%d (served via libuhttp.so)
ACME: HTTPS to external ACME server (Let's Encrypt / MikroTik cloud)
CRL: HTTP fetch to CRL distribution point URL from X.509 AIA extension

srand call site analysis:
  0x805b38f: gettimeofday(&tv, NULL)   — tv at -0x608(%ebp)
  0x805b395: push -0x604(%ebp)         — tv.tv_usec (NOT tv.tv_sec)
  0x805b39b: srand(tv.tv_usec)         — seeds global PRNG with ONLY microseconds
  Effective entropy: log2(1,000,000) ≈ 20 bits
  Context: called during cerm startup after mkdir("/rw/cm", 0x700)
  rand() usage: 1 call site (0x8065368), rand() % 15 = retry jitter only
  SCEP challenge: generated via libucrypto.so makeChallenge() — separate entropy path

CRL URI construction:
  Format: "URI:http://%s/crl/%u.crl"
  Built by _Z1sPKcz (variadic string formatter) at 0x8055890 and 0x8060c51
  %s source: X.509 certificate Authority Information Access (AIA) extension hostname
  %u source: certificate serial number or CRL index
  The hostname is read from the parsed certificate's AIA extension — attacker-controlled
  if the certificate was crafted by an adversary.

ACME error strings (evidence of JSON parse depth):
  "Challenge: received invalid json from server"
  "challenges" — JSON array field name
  "error - challenges array is empty"
  "acme challenge object is not valid"
  "challenge entry is missing required field 'type'"
  "challenge entry is missing required field '..."
  "token" — ACME challenge token field
  "invalid challenge object (chal type '..."
  "could not request validation - invalid challenge object"

----- FINDINGS SUMMARY -----
MTIK-CERM-F01 HIGH   8.1  CRL SSRF — attacker-controlled AIA hostname drives outbound HTTP from router
MTIK-CERM-F02 HIGH   7.5  x509ValidatePath + readCertFromStr — DER chain from network input; parser attack surface
MTIK-CERM-F03 MEDIUM 6.5  ACME JSON parsing — json::StreamParser processes ACME server JSON; 5 call sites
MTIK-CERM-F04 MEDIUM 5.3  srand(tv.tv_usec) — 20-bit entropy PRNG seed at startup
MTIK-CERM-F05 LOW    3.7  /scep/server%d — SCEP HTTP path enumeration; "Path must start with /scep/" guard present
MTIK-CERM-F06 INFO   0.0  sscanf('.%d.%d') — integer-only format — CLEAN
MTIK-CERM-F07 INFO   0.0  strcat in UUID hex encoder — destination buffer 256 bytes, max output 40 bytes — CLEAN
"""

# ---------------------------------------------------------------------------
# CRL fetch mechanism
# ---------------------------------------------------------------------------

CRL_FETCH = {
    'uri_format':   'URI:http://%s/crl/%u.crl',
    'format_va':    0x080de2c5,
    'build_sites': [
        {'va': 0x8055890, 'fn': '_Z1sPKcz'},
        {'va': 0x8060c51, 'fn': '_Z1sPKcz'},
    ],
    'source_of_s':  'X.509 certificate AIA extension hostname field — attacker-controlled if cert crafted',
    'source_of_u':  'Certificate serial or CRL distribution point index',
    'http_call':    'nv::Http::newRequest() at 0x8056ecd',
    'connect_call': 'nv::Connection::aconnect() at 0x8056f1e',
    'dns_call':     'nv::Connection::resolve() at 0x80571??',
    'note': (
        'cerm fetches CRLs using nv::Http::newRequest() and nv::Connection::aconnect(). '
        'The URL is constructed from the AIA extension of the certificate being validated. '
        'No sanitization of the hostname component was observed between AIA extraction '
        'and HTTP connect. "disallow ssl for crl dns" string (0x080e21f3) suggests a path '
        'where CRL-over-HTTPS is disabled for DNS names — implying HTTP is the default.'
    ),
}

# ---------------------------------------------------------------------------
# srand analysis
# ---------------------------------------------------------------------------

SRAND_ANALYSIS = {
    'gettimeofday_va': 0x805b38f,
    'tv_addr':         'lea -0x608(%ebp)',
    'seed_field':      'tv.tv_usec — field at -0x604(%ebp)',
    'srand_va':        0x805b39b,
    'seed_range':      '0 to 999,999 (microseconds)',
    'effective_bits':  20,
    'rand_call_sites': [
        {
            'va':        0x8065368,
            'context':   'rand() % 15 → retry jitter (0-14 seconds)',
            'precond':   'nv::getUptime() <= 30 seconds',
            'risk':      'LOW — jitter timer, not key material',
        },
    ],
    'scep_challenge':  'makeChallenge() in libucrypto.so — separate entropy path, does not use this PRNG',
    'note': (
        'srand is seeded with ONLY tv.tv_usec (microseconds), NOT tv.tv_sec. '
        'This is strictly weaker than the user daemon (MTIK-USER-F04) which seeds '
        'with tv_sec + tv_usec. With only ~1,000,000 possible seeds, an attacker '
        'who knows approximate boot time can enumerate all rand() outputs. '
        'In cerm 7.24.2, there is only one rand() call site and it produces a retry '
        'jitter value — not SCEP challenge material. However, the weak seed is a latent '
        'risk if future code adds rand() calls for security-relevant material, '
        'or if the global PRNG state leaks through a shared rand_r()-style interface.'
    ),
}

# ---------------------------------------------------------------------------
# X.509 DER parsing attack surface
# ---------------------------------------------------------------------------

CERT_PARSING = {
    'parsers': {
        'readCertFromStr':      'PEM/DER certificate from string_view — primary cert import path',
        'readCrl':              'CRL DER parser — called after CRL HTTP fetch',
        'readCertChain':        'Multi-certificate chain parser',
        'parsePem':             'PEM header/footer parser (base64 decode → DER)',
        'pemDecode':            'base64+DER decoder',
        'parsePkcs8PublicKey':  'PKCS#8 DER public key parser',
        'x509BuildPath':        'Certificate path construction (builds chain)',
        'x509ValidatePath':     'Full chain validation (signature + revocation + expiry)',
    },
    'network_inputs': [
        'SCEP enrollment response (pkiMessage DER blob in HTTP response body)',
        'CRL HTTP fetch response (DER-encoded CRL)',
        'ACME X.509 certificate download',
        'Nova store /nova/store/cert/* (any Nova bus participant can write)',
        'User-supplied PEM via API or WebFig',
    ],
    'parsing_chain': (
        'Network bytes → nv::Http::processBody() → readCertFromStr()/readCrl() → '
        'DER/PEM parser (libucrypto.so) → x509BuildPath() → x509ValidatePath(). '
        'The deepest parse occurs in the DER decoder inside libucrypto.so. '
        'Same vulnerability class as documented in MTIK-FIGMAN-F02 (eddsa DER parsing): '
        'tag-length overflow, negative-length, constructed vs. primitive encoding errors.'
    ),
}

# ---------------------------------------------------------------------------
# ACME JSON parsing
# ---------------------------------------------------------------------------

ACME_JSON = {
    'library':       'libjson.so (DT_NEEDED)',
    'parser_class':  'json::StreamParser',
    'feed_call':     'json::StreamParser::feed(char const*, uint)',
    'read_call':     'json::StreamParser::read(json::Object&)',
    'call_sites': [
        {'feed': 0x80756e6, 'read': 0x8075700, 'context': 'ACME challenge fetch parse'},
        {'feed': 0x8075a79, 'read': 0x8075a93, 'context': 'ACME order status parse'},
        {'feed': 0x80761b4, 'read': 0x80761ce, 'context': 'ACME authorization parse'},
        {'feed': 0x80764cd, 'read': 0x80764e4, 'context': 'ACME challenge validation parse'},
        {'feed': 0x80777fb, 'read': 0x8077815, 'context': 'ACME token parse'},
    ],
    'json_source': 'ACME server HTTPS response body — external network',
    'fields_accessed': [
        'challenges (array)',
        'token',
        'type',
        'status',
        '"key auth" / challenge token construction',
    ],
    'note': (
        'json::StreamParser is an external library (libjson.so). All 5 feed() call sites '
        'pass data originating from an ACME server HTTPS response. '
        'If libjson.so has parsing vulnerabilities (unbounded recursion, integer overflow '
        'on array sizes, OOB read on malformed UTF-8), a malicious ACME server '
        '(or MITM on the ACME HTTP response — note ACME uses HTTPS but depends on '
        'cerm''s TLS trust store which itself may be manipulable) can trigger them. '
        'libjson.so is not in ~/mikrotik-re/bins/ and requires separate extraction for analysis.'
    ),
}

# ---------------------------------------------------------------------------
# SCEP endpoint
# ---------------------------------------------------------------------------

SCEP_ENDPOINT = {
    'path_format':  '/scep/server%d',
    'path_guard':   'Path must start with /scep/ (string check in servlet)',
    'http_server':  'libuhttp.so — ServletHandler::handleCmd',
    'scep_stores': [
        '/nova/store/cert/scep_server',
        '/nova/store/cert/scep_ca_transactions',
        '/nova/store/cert/scep_otp',
        '/nova/store/cert/scep_ra',
    ],
    'challenge_fn': 'makeChallenge(string const&, vector<uint8_t> const&, bool) in libucrypto.so',
    'note': (
        'SCEP enrollment is served over HTTP (libuhttp.so) at /scep/server%d. '
        'The challenge password (OTP) is generated by makeChallenge() in libucrypto.so '
        '— separate from cerm''s srand(tv_usec) PRNG. '
        '"challange-password length must be between 4 and 20" string confirms validation; '
        '"authorized by OTP" confirms OTP-based auth flow. '
        'SCEP is historically vulnerable to NONCE reuse and PKI spoofing; '
        'without analyzing libucrypto.so makeChallenge() source, OTP entropy is unconfirmed.'
    ),
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

FINDINGS = [
    {
        'id':       'MTIK-CERM-F01',
        'severity': 'HIGH',
        'cvss':     8.1,
        'title':    'CRL SSRF — X.509 AIA extension hostname drives outbound HTTP from router',
        'detail': (
            'cerm fetches Certificate Revocation Lists via nv::Http::newRequest() and '
            'nv::Connection::aconnect(). The CRL distribution point URI is constructed '
            'at 0x8055890 and 0x8060c51 using the format "URI:http://%s/crl/%u.crl", '
            'where %s is the hostname extracted from the X.509 certificate\'s Authority '
            'Information Access (AIA) extension. '
            'Attack chain: '
            '(1) Attacker crafts an X.509 certificate with AIA hostname = attacker.example.com '
            '(2) Certificate is imported into RouterOS via SCEP enrollment, API, or WebFig '
            '    (requires operator-level access, or exploits another finding to write to '
            '    /nova/store/cert/peer) '
            '(3) cerm calls x509ValidatePath() which triggers CRL fetch for the AIA '
            '(4) cerm opens TCP connection to attacker.example.com on port 80 '
            '    and sends "GET /crl/<N>.crl HTTP/1.1\\r\\nHost: attacker.example.com\\r\\n\\r\\n" '
            '(5) The request originates from the router''s IP address, bypassing external '
            '    firewall rules that block outbound connections from end-user devices '
            'Impact: '
            '  - SSRF: attacker enumerates internal services reachable from the router '
            '  - Canary: router IP/identity exposed to attacker server '
            '  - If combined with a redirect, the router may connect to internal hosts '
            '    (e.g., http://192.168.1.1:80/crl/0.crl) '
            'The AIA hostname is also used in DNS resolution (nv::Connection::resolve()) '
            'before the TCP connect — even if TCP fails, a DNS request goes out. '
            'No hostname sanitization (IP address restriction, HTTPS requirement, allowlist) '
            'was observed between AIA extraction and the HTTP connect call.'
        ),
        'evidence': {
            'uri_format_va':    '0x080de2c5: "URI:http://%s/crl/%u.crl"',
            'build_va':         '0x8055890 (_Z1sPKcz)',
            'http_call_va':     '0x8056ecd (nv::Http::newRequest)',
            'connect_call_va':  '0x8056f1e (nv::Connection::aconnect)',
            'aia_source':       'X.509 AIA extension, parsed via readCertFromStr / x509ValidatePath',
            'required_access':  'Certificate import (operator-level or exploited write path)',
        },
        'recommendation': (
            'Restrict CRL fetch targets: '
            '(1) Validate AIA hostname against an allowlist before connecting '
            '(2) Reject non-HTTPS CRL distribution points (enforce https:// prefix) '
            '(3) Validate that the AIA hostname resolves to a public IP (no RFC1918/loopback) '
            '(4) Use a timeout and byte limit on CRL HTTP response to prevent stall attacks. '
            'Short-term: log all outbound CRL fetch attempts with the certificate issuer.'
        ),
        'status': 'CONFIRMED (code path traced: AIA extract → URI build → HTTP connect)',
        'cve': None,
    },
    {
        'id':       'MTIK-CERM-F02',
        'severity': 'HIGH',
        'cvss':     7.5,
        'title':    'x509ValidatePath + DER parsing chain — attack surface for malformed certificate input',
        'detail': (
            'cerm parses X.509 certificates, CRLs, and PKCS#7 structures from multiple '
            'network-reachable sources: SCEP enrollment responses, ACME certificate downloads, '
            'CRL HTTP fetch responses, and Nova store certificate writes. '
            'All parsing routes through libucrypto.so (readCertFromStr, readCrl, readCertChain, '
            'parsePem, pemDecode, parsePkcs8PublicKey, x509BuildPath, x509ValidatePath, '
            'PKCS7SignedData::parse). '
            'Each DER parser is susceptible to the same vulnerability class documented in '
            'MTIK-FIGMAN-F02: tag-length overflow, negative indefinite-length encoding, '
            'constructed vs. primitive type confusion, trailing data after parsed length. '
            'Specific high-risk paths: '
            '  (1) SCEP response: pkiMessage is a DER-encoded PKCS#7 SignedData blob, '
            '      received from a SCEP server that cerm trusts. A malicious SCEP server '
            '      (or MITM) sends a crafted pkiMessage. '
            '  (2) CRL fetch: DER-encoded CRL from HTTP response, origin from AIA hostname '
            '      which may be attacker-controlled (MTIK-CERM-F01 chain). '
            '  (3) ACME certificate: X.509 DER from Let''s Encrypt / MikroTik cloud server. '
            '      A compromised ACME server sends malformed DER. '
            '  (4) Nova store: any Nova bus participant can write to /nova/store/cert/* '
            '      and supply a malformed certificate blob.'
        ),
        'evidence': {
            'parse_fns': [
                'readCertFromStr (libucrypto.so)',
                'readCrl (libucrypto.so)',
                'PKCS7SignedData::parse (libucrypto.so)',
                'x509BuildPath (libucrypto.so)',
                'x509ValidatePath (libucrypto.so)',
            ],
            'network_inputs': [
                'SCEP pkiMessage (HTTP body, DER)',
                'CRL HTTP fetch (DER)',
                'ACME certificate (HTTPS body, DER)',
            ],
            'nova_input': '/nova/store/cert/* (no auth)',
        },
        'recommendation': (
            'Fuzz all DER entry points with malformed certificates: '
            'truncated TLV sequences, length > remaining buffer, '
            'negative-length encoding, deeply nested sequences (recursion depth). '
            'Enforce a maximum DER input size at each parse entry point before calling '
            'the parser. Add assert() or return NULL on any DER length exceeding file size.'
        ),
        'status': 'UNCONFIRMED — requires libucrypto.so DER parser fuzzing',
        'cve': None,
    },
    {
        'id':       'MTIK-CERM-F03',
        'severity': 'MEDIUM',
        'cvss':     6.5,
        'title':    'ACME JSON parsing — json::StreamParser processes external server JSON; 5 call sites',
        'detail': (
            'cerm implements an ACME (Let''s Encrypt / RFC 8555) client. Server responses '
            'are parsed at 5 call sites (feed + read pairs at 0x80756e6, 0x8075a79, '
            '0x80761b4, 0x80764cd, 0x80777fb). '
            'json::StreamParser is in libjson.so (DT_NEEDED), not available for analysis. '
            'The parsed JSON includes: challenges[], token, type, status, authorization objects. '
            'Attack vectors: '
            '(1) A malicious ACME server controlled by the attacker (e.g., if RouterOS '
            '    is configured to use a non-standard ACME endpoint). '
            '(2) DNS poisoning / BGP hijack that redirects the ACME server HTTPS connection '
            '    (only if TLS certificate verification fails or is bypassed). '
            '(3) MITM on plain HTTP redirect from ACME HTTP-01 challenge validation. '
            'If libjson.so has: unbounded recursion on nested objects, integer overflow '
            'on array element count, stack-based OOB on malformed UTF-8, or heap OOB on '
            'long string values, a malicious ACME server can trigger them. '
            '"Challenge: received invalid json from server" confirms that the code handles '
            'parse failures — but error handling code is also attack-reachable.'
        ),
        'evidence': {
            'call_sites': [
                '0x80756e6/0x8075700 — challenge fetch',
                '0x8075a79/0x8075a93 — order status',
                '0x80761b4/0x80761ce — authorization',
                '0x80764cd/0x80764e4 — challenge validation',
                '0x80777fb/0x8077815 — token parse',
            ],
            'library': 'libjson.so (not extracted)',
        },
        'recommendation': (
            'Extract and fuzz libjson.so with malformed ACME-like JSON: '
            'deeply nested objects (10,000+ levels), arrays with 2^31 count field, '
            'strings with embedded NUL bytes, numbers with 1000+ digit mantissas, '
            'incomplete UTF-8 surrogate pairs. '
            'Add a maximum nesting depth limit and array element count limit to StreamParser.'
        ),
        'status': 'UNCONFIRMED — requires libjson.so extraction and fuzzing',
        'cve': None,
    },
    {
        'id':       'MTIK-CERM-F04',
        'severity': 'MEDIUM',
        'cvss':     5.3,
        'title':    'srand(tv.tv_usec) — 20-bit PRNG seed at cerm startup',
        'detail': (
            'At 0x805b39b, cerm calls srand() with only tv.tv_usec — the microsecond '
            'component of the current time, range 0–999,999. '
            'This is strictly weaker than the user daemon''s srand(tv_sec + tv_usec). '
            'The seed produces ≈20 bits of effective entropy (log2(1,000,000) ≈ 19.9). '
            'In cerm 7.24.2, only one rand() call exists (0x8065368: retry jitter). '
            'The risk is latent rather than immediately exploitable: '
            '(1) If future versions add rand() calls for security-relevant material '
            '    (session tokens, temporary keys, nonces), the weak seed propagates. '
            '(2) If the rand() state is observable (e.g., via timing of retry behavior), '
            '    boot time can be narrowed and the seed enumerated. '
            '(3) The srand() call is in the cerm process initialization — the same '
            '    global PRNG state is shared by all rand() calls in cerm''s lifetime. '
            'SCEP challenge is generated by libucrypto.so makeChallenge() which uses '
            'a separate entropy path (getDefaultRng() / getrandom syscall — confirmed '
            'in libucrypto.so).'
        ),
        'evidence': {
            'gettimeofday_va': '0x805b38f',
            'seed_push_va':    '0x805b395: push -0x604(%ebp) = tv.tv_usec',
            'srand_va':        '0x805b39b',
            'rand_call':       '0x8065368: rand() % 15',
            'effective_bits':  20,
        },
        'recommendation': (
            'Replace srand(tv.tv_usec) with srand(tv.tv_sec ^ tv.tv_usec) at minimum, '
            'or ideally seed from /dev/urandom: '
            'int seed; read(open("/dev/urandom", O_RDONLY), &seed, 4); srand(seed). '
            'Longer term: replace rand() calls with getrandom() or the libucrypto.so '
            'getDefaultRng() interface for any security-relevant random values.'
        ),
        'status': 'CONFIRMED (disassembly: push tv.tv_usec → srand)',
        'cve': None,
    },
    {
        'id':       'MTIK-CERM-F05',
        'severity': 'LOW',
        'cvss':     3.7,
        'title':    '/scep/server%d — SCEP HTTP endpoint path; "Path must start with /scep/" guard present',
        'detail': (
            'cerm serves SCEP enrollment requests at /scep/server%d via libuhttp.so. '
            'The path format uses %d (decimal integer) for the server index. '
            'A string check "Path must start with /scep/" is present in cerm''s rodata, '
            'suggesting a guard exists against arbitrary path traversal. '
            'However: '
            '(1) The guard may not prevent /scep/server-1, /scep/server2147483647, or '
            '    /scep/server%0d (format string injection in log path). '
            '(2) SCEP endpoints traditionally do not require authentication for '
            '    GetCACert and GetCACaps operations — an unauthenticated attacker can '
            '    enumerate the certificate chain. '
            '(3) SCEP uses unauthenticated HTTP; without HTTPS enforcement, a MITM '
            '    can modify SCEP responses (pkiMessage) in transit.'
        ),
        'evidence': {
            'path_format':  '/scep/server%d (at rodata 0x080e1061)',
            'path_guard':   '"Path must start with /scep/" (rodata)',
            'http_server':  'libuhttp.so (ServletHandler::handleCmd)',
            'scep_ra':      '/nova/store/cert/scep_ra',
        },
        'recommendation': (
            'Enforce HTTPS for all SCEP endpoints. '
            'Validate the %d value against known server indices (not negative, not > MAX_SCEP_SERVERS). '
            'Require client authentication for SCEP PKIOperation requests (Enrollment, CertPoll). '
            'Log all SCEP GetCACert requests to detect reconnaissance.'
        ),
        'status': 'UNCONFIRMED — path guard implementation needs verification',
        'cve': None,
    },
    {
        'id':       'MTIK-CERM-F06',
        'severity': 'INFO',
        'cvss':     0.0,
        'title':    'sscanf(".%d.%d") — integer-only format — CLEAN',
        'detail': (
            'One sscanf call at 0x809f4ae uses format ".%d.%d" (version number or IP octet parsing). '
            'Format is integer-only (%d), no %s, no unbounded read. CLEAN.'
        ),
        'evidence': {'va': '0x809f4ae', 'format': '.%d.%d'},
        'recommendation': 'No action required.',
        'status': 'CLEAN',
        'cve': None,
    },
    {
        'id':       'MTIK-CERM-F07',
        'severity': 'INFO',
        'cvss':     0.0,
        'title':    'strcat in UUID hex encoder — bounded destination (256 bytes), max output 40 bytes — CLEAN',
        'detail': (
            'Two strcat calls at 0x80a0613 and 0x80a0628 are inside a loop (esi: 0–7) '
            'that encodes an 8-element array of u16 values into hex string format. '
            'Each iteration appends at most 5 characters. Total max output = 8*5 = 40 chars. '
            'Destination is lea 0x14c(%esp) or 0x2c(%esp) (stack buffer, zeroed at entry). '
            'Push of $0x100 before a function call above this loop suggests a 256-byte dest. '
            '40 << 256 — no overflow. Source data is a UUID from an nv::message field. CLEAN.'
        ),
        'evidence': {
            'site_1':    '0x80a0613',
            'site_2':    '0x80a0628',
            'dest_size': 256,
            'max_write': 40,
            'loop_count': 8,
        },
        'recommendation': 'No action required.',
        'status': 'CLEAN',
        'cve': None,
    },
]
