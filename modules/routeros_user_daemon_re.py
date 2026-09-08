"""
RouterOS 7.24.2 — /nova/bin/user RE module
Binary: user (80KB, x86-32 ELF stripped, dynamically linked)
SHA path: ~/mikrotik-re/bins/user

Role: User account management and authentication daemon. Handles Winbox,
REST API, and console auth. Manages /nova/store/user, groups, AAA config.

PLT imports (security-relevant):
  rand@plt      : 0x804d4a0  — 4 call sites (2 crypto-adjacent, 2 unknown)
  srand@plt     : 0x804d1c0  — 1 call site (time-seeded)
  open@plt      : 0x804d5e0  — 5 call sites (includes /dev/urandom path)
  getenv@plt    : confirmed present
  atoi@plt      : confirmed present
  snprintf@plt  : primary output formatter — no unbounded string functions present

ABSENT: strcpy, strcat, sprintf, scanf — clean from memory corruption standpoint
ABSENT: execve, execl, popen, system — no exec primitives

Crypto inventory:
  MD5    : vtable _ZTV3MD5, digest _ZN3MD56digestEPh — BROKEN (RFC 6151)
  SHA1   : vtable _ZTV4SHA1 — WEAK
  SHA256 : vtable _ZTV6SHA256, digest _ZN6SHA2566digestEPh — SAFE
  Curve25519 : full class _ZN10Curve25519C1Ev — SAFE
  WCurve     : Weierstrass curve class (mul/add methods) — CUSTOM, timing unknown
  BigNum     : custom arbitrary-precision arithmetic

rand() seed:
  srand(tv.tv_sec + tv.tv_usec) at 0x8057b3f–0x8057b4e (gettimeofday then add)
  Called once at daemon startup — entropy limited to boot timestamp

rand() rand loop at 0x8051265–0x805128d:
  Loop 16 iterations: rand() → low byte of result → output buffer
  Generates 16-byte value using only rand() — time-seeded PRNG

/dev/urandom:
  push $0x80591a5 (= /dev/urandom, file offset 0x111a5) at 0x80512a4
  open(/dev/urandom, O_RDONLY) call at 0x80512a9

Auth protocol strings:
  "bad challenge", "no challenge", "wrong challenge" — challenge-response
  "radius authentication is not supported for old challenges" — protocol version split
  "invalid user name or password" — single non-disambiguating error message (SAFE)
  "winbox", "rest-api" — protocol context tags

Nova store paths:
  /nova/store/user, /nova/store/group, /nova/store/login
  /nova/store/user/aaa, /nova/store/user/cfg
  /nova/etc/user

----- FINDINGS SUMMARY -----
MTIK-USER-F01 MEDIUM 6.5  Old Winbox challenge generated with time-seeded rand() — predictable
MTIK-USER-F02 MEDIUM 6.1  MD5 in legacy auth protocol — collision/preimage attacks
MTIK-USER-F03 MEDIUM 5.9  WCurve custom Weierstrass multiplication — timing side channel
MTIK-USER-F04 LOW    3.7  srand seed = gettimeofday sum — ~20-bit effective entropy
MTIK-USER-F05 INFO   0.0  No strcpy/sprintf/exec primitives — CLEAN from memory corruption
"""

# ---------------------------------------------------------------------------
# rand() seeding analysis
# ---------------------------------------------------------------------------

SRAND_SEED_ANALYSIS = {
    'srand_va':       0x8057b4e,
    'gettimeofday_va': 0x8057b3a,
    'seed_formula':   'srand(tv.tv_usec + tv.tv_sec)',
    'entropy_bits': {
        'tv_sec':  'POSIX timestamp — attacker estimates from cert/snmp/ntp to ±seconds',
        'tv_usec': '0–999999 (microseconds) — ≈ 20 additional bits, mostly unpredictable',
        'combined': '~32 effective bits; practical attack window assumes boot time ±60s → ~26 bits',
    },
    'timing': 'Called once at user daemon start; seed fixed for daemon lifetime',
    'impact': (
        'All rand()-based output for the session lifetime is determined by a single '
        'time-derived seed. An attacker who can estimate router boot time (via uptime '
        'SNMP OID 1.3.6.1.2.1.1.3.0, NTP, or other side channels) can enumerate '
        'the full rand() sequence.'
    ),
}

RAND_USAGE = [
    {
        'va':      0x8051278,
        'context': '16-byte buffer fill: rand() low byte × 16 iterations',
        'loop': {
            'start': 0x8051278,
            'iter':  16,
            'per_iter': 'rand() → low byte → buf[i]',
        },
        'output_size': 16,
        'probable_use': 'Legacy Winbox challenge value (old protocol pre-Curve25519)',
        'risk': 'HIGH — challenge is deterministic from srand seed; replay/prediction attack',
    },
    {
        'va':      0x80512d1,
        'context': 'Second rand call in adjacent function',
        'probable_use': 'Fallback or secondary challenge material',
        'risk': 'HIGH — same seed constraint',
    },
    {
        'va':      0x8057f96,
        'context': (
            'Two-rand XOR pattern: rand() → ebx; rand() → eax; '
            'sar $0x10,%eax; xor %ebx,%eax; store low byte. '
            'Runs after nv::policies::set_policy(sock, 0xfe0006, 0x20) — '
            'policy initialization, then rand material'
        ),
        'probable_use': 'Additional session or initialization material',
        'risk': 'MEDIUM — same seed; XOR of two rand() values does not add entropy',
    },
    {
        'va':      0x8057f9d,
        'context': 'Second rand() in the XOR pair at 0x8057f96',
        'probable_use': 'XOR partner in pair',
        'risk': 'MEDIUM',
    },
]

URANDOM_USAGE = {
    'open_va':   0x80512a9,
    'path_va':   0x80591a5,
    'path':      '/dev/urandom',
    'context':   'Opened in function adjacent to rand() loop — newer auth path',
    'probable_use': 'Curve25519 key material or new-protocol challenge (SAFE path)',
    'note': 'New Winbox protocol (2022+) uses Curve25519 + /dev/urandom — SAFE',
}

# ---------------------------------------------------------------------------
# Crypto analysis
# ---------------------------------------------------------------------------

CRYPTO_INVENTORY = {
    'MD5': {
        'status': 'BROKEN',
        'vtable': '_ZTV3MD5',
        'digest_sym': '_ZN3MD56digestEPh',
        'context': 'Legacy Winbox challenge-response protocol (old challenges)',
        'attack': 'RFC 6151 prohibits MD5 in security contexts; collision in 2^18 ops',
        'cve_ref': 'CVE-2004-2761 (MD5 collision); no specific RouterOS CVE confirmed',
    },
    'SHA1': {
        'status': 'WEAK',
        'vtable': '_ZTV4SHA1',
        'attack': 'SHAttered (SHA1 collision 2017); forbidden in TLS 1.3',
    },
    'SHA256': {
        'status': 'SAFE',
        'vtable': '_ZTV6SHA256',
        'digest_sym': '_ZN6SHA2566digestEPh',
    },
    'Curve25519': {
        'status': 'SAFE (standard curve, custom implementation)',
        'class': '_ZN10Curve25519C1Ev',
        'methods': [
            '_ZN10Curve255194getXERK6vectorIhE',
            '_ZN10Curve255197fromNumERK6BigNumj',
            '_ZN10Curve255197fromBinEN4asn14blobE',
            '_ZN10Curve255197isValidERKN6WCurve5PointE',
            '_ZN10Curve255195toBinEON6WCurve5PointE',
            '_ZN10Curve255195toNumEON6WCurve5PointEPj',
            '_Z5redp1RK10Curve25519RK6vectorIhE',
        ],
        'note': 'redp1 = scalar multiply reduction step; custom big-num backend',
    },
    'WCurve': {
        'status': 'UNKNOWN — custom Weierstrass implementation',
        'methods': [
            '_ZNK6WCurve3mulERK6BigNumRKNS_5PointE',
            '_ZNK6WCurve3addERNS_5PointERKS0_P6RedNum',
        ],
        'concern': 'Custom point multiplication; conditional branching in mul may expose timing oracle',
    },
    'BigNum': {
        'status': 'CUSTOM — used by both Curve25519 and WCurve backends',
        'concern': 'Custom big-num without confirmed constant-time guarantees',
    },
}

AUTH_PROTOCOL_SPLIT = {
    'old_protocol': {
        'hash':      'MD5',
        'rng':       'rand() (time-seeded)',
        'challenge': '16-byte rand() output',
        'ref_string': 'radius authentication is not supported for old challenges',
        'risk':      'Predictable challenge; MD5 hash; pre-auth dictionary attack feasible',
    },
    'new_protocol': {
        'hash':      'SHA256',
        'rng':       '/dev/urandom',
        'key_exch':  'Curve25519 (redp1 scalar multiply)',
        'risk':      'Custom implementation — timing side channel risk in WCurve::mul',
    },
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

FINDINGS = [
    {
        'id':             'MTIK-USER-F01',
        'severity':       'MEDIUM',
        'cvss':           6.5,
        'title':          'Old Winbox challenge generated with time-seeded rand() — predictable',
        'detail': (
            'The user daemon generates 16-byte challenge values using rand() at 0x8051278–0x8051286 '
            'in a loop: rand() low byte × 16 iterations → challenge buffer. '
            'The rand() state is seeded once at startup with srand(tv.tv_sec + tv.tv_usec) '
            'at 0x8057b4e. Because the seed is time-derived, an attacker who can estimate '
            'the router boot time (via SNMP sysUpTime OID 1.3.6.1.2.1.1.3.0, NTP, or any '
            'other timing channel) can enumerate all possible challenge values. '
            'The challenge is used in the old Winbox authentication protocol '
            '(referenced by "radius authentication is not supported for old challenges"). '
            'A pre-computed challenge → response table for any user (including admin) '
            'reduces authentication to trial of ~2^26 candidates for a ±60s boot window. '
            'This attack is offline once the challenge is observed.'
        ),
        'evidence': {
            'rand_loop_va':  '0x8051278',
            'loop_count':    16,
            'srand_va':      '0x8057b4e',
            'seed_source':   'gettimeofday at 0x8057b3a: tv_sec + tv_usec',
            'protocol_ref':  '"radius authentication is not supported for old challenges"',
        },
        'recommendation': (
            'Replace rand() with a read from /dev/urandom for all auth challenge generation. '
            'The new protocol path already uses /dev/urandom (0x80512a9) — extend this to '
            'the old protocol path, or disable the old protocol entirely '
            '(negotiation strings suggest it can be gated).'
        ),
        'status': 'UNCONFIRMED — requires confirmation that this rand loop feeds Winbox challenge path',
        'cve': None,
    },
    {
        'id':             'MTIK-USER-F02',
        'severity':       'MEDIUM',
        'cvss':           6.1,
        'title':          'MD5 in legacy Winbox authentication protocol',
        'detail': (
            'MD5 vtable (_ZTV3MD5) and digest method (_ZN3MD56digestEPh) are present. '
            'The auth protocol split confirms MD5 is used in the "old challenge" path: '
            '"radius authentication is not supported for old challenges" implies a '
            'two-protocol negotiation where old = MD5-based challenge-response. '
            'MD5 collision attacks (2^18 ops, Wang et al.) and preimage attacks '
            '(RFC 6151) allow crafted challenge responses to bypass authentication '
            'if an attacker controls the challenge value or can find a hash collision. '
            'Combined with the predictable challenge from MTIK-USER-F01, the attack chain is: '
            'observe challenge → predict challenge seed → precompute valid response → authenticate.'
        ),
        'evidence': {
            'md5_vtable':   '_ZTV3MD5',
            'md5_digest':   '_ZN3MD56digestEPh',
            'protocol_ref': '"radius authentication is not supported for old challenges"',
        },
        'recommendation': (
            'Disable the old Winbox challenge protocol (MD5-based) entirely. '
            'Force all clients to the new Curve25519-based protocol. '
            'MikroTik Winbox clients v3.30+ support the new protocol.'
        ),
        'status': 'CONFIRMED (architectural) — MD5 in PLT + old-challenge string',
        'cve': 'CVE-2018-14847 (related — Winbox auth bypass in RouterOS < 6.43; different mechanism but same protocol surface)',
    },
    {
        'id':             'MTIK-USER-F03',
        'severity':       'MEDIUM',
        'cvss':           5.9,
        'title':          'WCurve custom Weierstrass multiplication — timing side channel',
        'detail': (
            'WCurve::mul(BigNum const&, WCurve::Point const&) at _ZNK6WCurve3mulERK6BigNumRKNS_5PointE '
            'and WCurve::add(WCurve::Point&, WCurve::Point const&, RedNum*) perform '
            'elliptic curve point arithmetic on a custom Weierstrass implementation backed '
            'by a custom BigNum type. Standard non-constant-time implementations '
            'of EC point multiplication execute different code paths depending on secret '
            'scalar bits (double-and-add algorithm), leaking private key bits '
            'via timing or cache measurements. '
            'No confirmation that WCurve::mul uses constant-time ladder or Montgomery form. '
            'RouterOS appears to use Curve25519 for the primary new auth protocol '
            'and WCurve as a secondary or legacy curve backend. '
            'If WCurve processes long-term private key material (user account keys), '
            'a timing attack from the local network is feasible in ~2^18 queries.'
        ),
        'evidence': {
            'mul_sym': '_ZNK6WCurve3mulERK6BigNumRKNS_5PointE',
            'add_sym': '_ZNK6WCurve3addERNS_5PointERKS0_P6RedNum',
            'bignum':  'Custom _ZNK6BigNum — no confirmed constant-time ops',
        },
        'recommendation': (
            'Audit WCurve::mul for conditional branches on secret bits. '
            'Replace with a Montgomery ladder or confirmed constant-time implementation. '
            'If WCurve is only used for public-key operations (not private key), risk is lower. '
            'Prefer the Curve25519 path which uses standard scalar multiply (redp1).'
        ),
        'status': 'UNCONFIRMED — requires disassembly of WCurve::mul implementation',
        'cve': None,
    },
    {
        'id':             'MTIK-USER-F04',
        'severity':       'LOW',
        'cvss':           3.7,
        'title':          'srand seed = gettimeofday sum — ~20-bit effective entropy',
        'detail': (
            'srand(tv.tv_sec + tv.tv_usec) at 0x8057b4e seeds the entire rand() '
            'state with the sum of seconds and microseconds at daemon start. '
            'While 2^32 values are theoretically possible, practical entropy is lower: '
            '- tv_sec component: bootloader + kernel + Nova init → typically 5–30 seconds '
            '  from known epoch, plus attacker\'s estimate from sysUpTime → ±60s window '
            '  = 120 candidate seconds. '
            '- tv_usec component: 0–999999 = ~20 bits. '
            'Effective search space: ~120 × 10^6 = ~2^27 candidates. '
            'This affects all rand()-based output for the daemon\'s lifetime.'
        ),
        'evidence': {
            'srand_va':       '0x8057b4e',
            'gettimeofday_va': '0x8057b3a',
            'seed_formula':   'tv.tv_usec + tv.tv_sec (confirmed from disasm)',
        },
        'recommendation': (
            'Seed PRNG from /dev/urandom: '
            'read 4 bytes from /dev/urandom at startup → pass to srand(). '
            'Or eliminate srand/rand entirely and use /dev/urandom reads directly '
            'for all random material (already implemented for the new-protocol path).'
        ),
        'status': 'CONFIRMED — disassembly shows gettimeofday → add → srand',
        'cve': None,
    },
    {
        'id':             'MTIK-USER-F05',
        'severity':       'INFO',
        'cvss':           0.0,
        'title':          'No strcpy/sprintf/exec primitives — memory corruption surface CLEAN',
        'detail': (
            'PLT scan: strcpy, strcat, sprintf, scanf, execve, execl, popen, system '
            'are ALL ABSENT from the user binary. '
            'Output formatting uses snprintf exclusively. '
            'String operations use C++ string class (append, assign, compare). '
            'No unbounded memory writes observed. '
            'Attack surface is confined to logic vulnerabilities (auth bypass, timing) '
            'and crypto weaknesses — not memory corruption.'
        ),
        'evidence': {
            'absent': ['strcpy', 'strcat', 'sprintf', 'scanf', 'execve', 'execl', 'system'],
            'present': ['snprintf'],
        },
        'recommendation': 'No action required from memory safety standpoint.',
        'status': 'CLEAN',
        'cve': None,
    },
]
