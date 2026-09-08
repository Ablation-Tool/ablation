"""
RouterOS 7.24.2 — /nova/bin/figman RE module
Binary: figman (207KB, x86-32 ELF stripped, dynamically linked)
SHA path: ~/mikrotik-re/bins/figman

Role: Certificate manager, PKEX (Wi-Fi Easy Connect / DPP) key exchange daemon,
and CAPsMAN bundle manager. Manages device identity certificates (X.509),
performs peer certificate validation, runs the PKEX push-button and console
enrollment flows, handles CMR (Certificate Manager Remote) client upgrades,
and manages package download state in /rw/pckg/.download/.

PLT imports (security-relevant — full list):
  Network:
    socket, bind, listen, connect, accept4, sendmsg, recvmsg
    setsockopt, getsockopt, gethostname, socketpair
    fcntl, close, read, write
  Filesystem:
    open, stat, unlink, mkdir, rmdir, opendir, readdir, closedir
  Process:
    kill, __assert_fail
  Crypto (external symbols):
    _Z10createHashj              — hash factory: createHash(HashAlg id) → Hash*
    _Z12randomBigNumP6BigNumRKS_RK3Rng  — randomBigNum(BigNum*, BigNum const& max, Rng const&)
    _Z13getDefaultRngv           — getDefaultRng() → Rng const& (entropy source unknown)
    _Z14getAForECCurve5Curve     — getAForECCurve(Curve) → BigNum
    _Z14getBForECCurve5Curve     — getBForECCurve(Curve) → BigNum
    _Z18getECParamsForP256R6BigNumS0_R7ECPoint  — P-256 domain parameters
    _Z5HKPDFR4HashRK6vectorIhES4_S4_j  — HKDF(Hash&, key, salt, info, outlen)
    _Z15readCertFromStr11string_view    — readCertFromStr(string_view) → X509Certificate*
    _Z21encodePkcs8PrivateKeyRK10PrivateKey  — PKCS#8 DER encoder for private key
    _Z18getOSVersionNumberPjP6string    — version string extraction
    _ZN6AESSIV7encryptERK4spanIKhERK6vectorIS2_EPh   — AES-SIV::encrypt
    _ZN6AESSIV7decryptERK4spanIKhERK6vectorIS2_EPh   — AES-SIV::decrypt
    _ZN17Ed25519PrivateKey11initPrivateE6vectorIhE    — Ed25519 private key init from blob
    _ZN5eddsa14get_public_keyEN4asn14blobE            — eddsa::get_public_key(asn1::blob)
  WCurve (custom Weierstrass EC):
    _ZNK6WCurve3mulERK6BigNumRKNS_5PointE  — WCurve::mul(BigNum const&, Point const&)
    _ZNK6WCurve3addERNS_5PointERKS0_P6RedNum  — WCurve::add(Point&, Point const&, RedNum*)
    _ZNK6WCurve9isOnCurveERK6BigNumS2_ONS_5PointE  — WCurve::isOnCurve
    _ZNK6WCurve4toECEONS_5PointE   — WCurve::toEC (convert to standard ECPoint)
    _ZNK6WCurve6fromECERK7ECPoint  — WCurve::fromEC (convert from standard ECPoint)
    _ZN17MontgomeryReducerC1ERK6BigNum  — MontgomeryReducer ctor (modular reduction)
    _ZHMAC (HMACC2 + Hash base)
  m3 message bus:
    _ZN2m37message3putENS_7MidTypeEj4spanIKhEj  — m3::message::put(type, id, span, flags)
    _ZN2m37message3Rep3putENS_7MidTypeEj4spanIKhEj
    _ZN2m37message3Rep6putNumENS_7MidTypeEjy     — m3::message::Rep::putNum
    _ZN2m37message4read7consumeE...              — m3::message::read::consume callback
    _ZN2m37message5putvcEjj                      — m3::message::putvc (variable-length code)
    _ZN2m37message8writeRawE...
    _ZN2m37message7readRawE...
    _ZN2m37message11WriteHandle8putChunkE...
    _ZN2m37message6addRawE...
    _ZN2m37message15prepareToModifyEv
    _ZN2m39filterMsgERNS_7messageERK6vectorIjE   — m3::filterMsg (field filter)
    _ZN2m39fromraw32E...                         — m3::fromraw32 (wire → message)
    _ZN2m39fromraw64E...                         — m3::fromraw64
    _ZN2m36getrawEP4spanIKhEj                    — m3::getraw
    _ZN2m34eachE...                              — m3::each (iterator over message fields)
  Nova bridge:
    _ZN2nv12flat_message9m3flattenE4spanIKhEPN2m37messageE  — nv→m3 format bridge
    _ZN2nv10AsyncReget4stopEv
    _ZN2nv10AsyncReget5startERKNS_7messageE8functionIFvS3_EES6_j
  X.509 / DER:
    _ZN15X509Certificate12setPublicKeyERK9PublicKey
    _ZNK15X509Certificate14parsePublicKeyEv
    _ZN8X509Base4signERK10PrivateKey6HashID
    _ZTV15X509Certificate (vtable)
    _ZN10DerEncoder6addTagEjj
    _ZN10DerEncoder9updateLenEj

PKEX classes:
  PKEXConsole   — console-based enrollment (CLI-triggered)
  PKEXPushButton — push-button enrollment (hardware button or API)
  PKEXImpl      — shared PKEX protocol implementation
    authDeriveZ(BigNum const&, BigNum const&) → bool
      Derives the PKEX shared secret Z from two BigNums (private scalar + peer EC point).
      Uses WCurve::mul for Diffie-Hellman. Risk: constant-time unknown.
    reveal1(vector<unsigned char>&) → bool
      PKEX commitment reveal — sends bootstrap key commitment to peer.

CMR classes:
  cmr::ClntHandler — certificate manager remote client
  cmr::Upgr        — upgrade handler; init and dtor lambdas capture string_view slices

Peer connection classes:
  ConnImpl::recvMsg(uint, msg_view const&)   — raw socket → m3 message dispatch
  Peer::connRecvMsg(uint, msg_view const&)   — peer-level message handler
  ConnectSrc::onConnect(int, uint)           — new inbound connection handler

Bundle management:
  bundleCreate(Local*, Bundle::Cfg&, uint, nv::message const&)  — creates a package bundle
  newWork(Bundle*, uint) → BundleWork*                          — allocates bundle work item
  OpB::sendUpdate(uint, uint, m3::msg_view)                     — sends bundle status update

Nova store paths:
  /nova/store/figman/peer     — peer certificate records
  /nova/store/figman/store    — local certificate store
  /nova/store/figman/rule     — certificate validation rules
  /nova/store/figman/local    — local device identity
  /nova/store/figman/remote   — remote identity records
  /nova/store/figman/connect  — connection configurations
  /nova/store/cmrclnt/inst    — CMR client instance config
  /nova/etc/figman-extension  — extension config file (stat + open)

Package download paths:
  /rw/pckg/.download/         — download staging directory
  /rw/pckg/.download/IGNORE   — skip-list for installer
  /rw/pckg/.download/LOCK     — advisory lock file (check-then-use pattern)

Error strings:
  "not on curve"          — WCurve point validation failure
  "Q not on curve"        — PKEX peer public key not on curve
  "X'/Y' not on curve"    — PKEX intermediate point validation failure
  ": AES-SIV encrypt failed"
  ": AES-SIV decrypt failed"
  "no peer certificate"
  "failed to parse peer certificate"

----- FINDINGS SUMMARY -----
MTIK-FIGMAN-F01 HIGH   7.5  WCurve::mul timing side-channel — custom Weierstrass scalar mul; no constant-time evidence
MTIK-FIGMAN-F02 HIGH   7.2  eddsa::get_public_key(asn1::blob) — ASN.1 DER parsing of attacker-supplied blob
MTIK-FIGMAN-F03 MEDIUM 6.1  getDefaultRng() entropy unknown — randomBigNum key material potentially weak
MTIK-FIGMAN-F04 MEDIUM 5.9  nv::flat_message::m3flatten — format confusion bridge between nv:: and m3:: messages
MTIK-FIGMAN-F05 LOW    4.3  /rw/pckg/.download/LOCK — TOCTOU on package download staging
MTIK-FIGMAN-F06 INFO   0.0  AES-SIV authenticated encryption — standard algorithm, error path visible — CLEAN
MTIK-FIGMAN-F07 INFO   0.0  HKDF and HMAC — standard KDF/MAC primitives — CLEAN
"""

# ---------------------------------------------------------------------------
# WCurve — custom Weierstrass elliptic curve
# ---------------------------------------------------------------------------

WCURVE_ANALYSIS = {
    'class':      'WCurve',
    'methods': {
        'mul':       '_ZNK6WCurve3mulERK6BigNumRKNS_5PointE',
        'add':       '_ZNK6WCurve3addERNS_5PointERKS0_P6RedNum',
        'isOnCurve': '_ZNK6WCurve9isOnCurveERK6BigNumS2_ONS_5PointE',
        'toEC':      '_ZNK6WCurve4toECEONS_5PointE',
        'fromEC':    '_ZNK6WCurve6fromECERK7ECPoint',
    },
    'montgomery_reducer': '_ZN17MontgomeryReducerC1ERK6BigNum',
    'point_validation_strings': [
        'not on curve',
        'Q not on curve',
        "X'/Y' not on curve",
    ],
    'note': (
        'WCurve is a custom Weierstrass curve implementation. MontgomeryReducer is present, '
        'suggesting modular reduction uses Montgomery form — necessary for efficiency but '
        'not sufficient for constant-time execution. '
        'The critical question is whether WCurve::mul uses a constant-time scalar '
        'multiplication algorithm (e.g., Montgomery ladder, double-and-always-add) '
        'or a variable-time algorithm (e.g., square-and-multiply with conditional branches). '
        'Point validation strings ("not on curve", "Q not on curve") confirm that isOnCurve '
        'checks are present — this is correct. However, validation alone does not prevent '
        'timing attacks if mul is variable-time after validation passes. '
        'Used by: PKEXImpl::authDeriveZ for PKEX shared secret derivation.'
    ),
    'pkex_usage': {
        'authDeriveZ_sym': 'bool PKEXImpl::authDeriveZ(BigNum const&, BigNum const&)',
        'role': 'PKEX DH: Z = WCurve::mul(private_scalar, peer_EC_point). '
                'Z is the shared secret for PKEX key derivation. '
                'If mul is variable-time, timing of authDeriveZ leaks bits of private_scalar '
                'to a peer that can measure connection establishment latency.',
    },
}

# ---------------------------------------------------------------------------
# PKEX protocol
# ---------------------------------------------------------------------------

PKEX_ANALYSIS = {
    'classes': ['PKEXConsole', 'PKEXPushButton', 'PKEXImpl'],
    'authDeriveZ': {
        'sym':    'bool PKEXImpl::authDeriveZ(BigNum const&, BigNum const&)',
        'inputs': 'BigNum arg1 (private scalar), BigNum arg2 (peer EC point coordinate)',
        'output': 'bool (success/failure)',
        'uses':   'WCurve::mul — Weierstrass DH',
    },
    'reveal1': {
        'sym':    'bool PKEXImpl::reveal1(vector<unsigned char>&)',
        'role':   'PKEX commitment reveal phase — sends bootstrap public key commitment to peer',
        'output': 'serialized commitment into vector<h>',
    },
    'enrollment_flows': {
        'PKEXConsole':    'Triggered via CLI or API; attacker-accessible if console exposed',
        'PKEXPushButton': 'Triggered by hardware button or CAPsMAN push-button API',
    },
}

# ---------------------------------------------------------------------------
# eddsa / Ed25519
# ---------------------------------------------------------------------------

EDDSA_ANALYSIS = {
    'get_public_key_sym': '_ZN5eddsa14get_public_keyEN4asn14blobE',
    'private_key_init':   '_ZN17Ed25519PrivateKey11initPrivateE6vectorIhE',
    'note': (
        'eddsa::get_public_key(asn1::blob) takes a raw ASN.1 blob as input. '
        'asn1::blob is a span-like type wrapping a (ptr, len) pair; it is passed by value. '
        'The blob likely originates from a Nova message or a peer certificate exchange. '
        'ASN.1 DER parsing is historically a vulnerability-dense operation: '
        '  - Length field overflows (tag-length-value where length > remaining buffer) '
        '  - Negative-length handling (high bit set in definite-length encoding) '
        '  - Constructed vs. primitive encoding confusion '
        '  - Trailing-data tolerance (parser reads past end of declared length) '
        'If figman passes a blob from a peer message directly to get_public_key without '
        'pre-validating that the blob length matches the declared DER length, a crafted '
        'certificate from a peer during PKEX enrollment or CMR upgrade could trigger '
        'an OOB read or heap overflow inside the DER parser. '
        'readCertFromStr(string_view) is a second DER entry point (for PEM-encoded certs).'
    ),
    'attack_surfaces': [
        'PKEX peer certificate exchange (PKEXImpl::reveal1 sends cert; peer cert parsed on receipt)',
        'CMR upgrade (cmr::Upgr::init lambda processes peer certificate)',
        'Nova store /nova/store/figman/peer (peer cert stored as Nova message)',
    ],
}

# ---------------------------------------------------------------------------
# Rng entropy
# ---------------------------------------------------------------------------

RNG_ANALYSIS = {
    'getDefaultRng_sym': '_Z13getDefaultRngv',
    'randomBigNum_sym':  '_Z12randomBigNumP6BigNumRKS_RK3Rng',
    'randomBigNum_sig':  'void randomBigNum(BigNum*, BigNum const& max, Rng const&)',
    'note': (
        'getDefaultRng() returns a Rng object used for all BigNum key material generation. '
        'The Rng class implementation is inside figman or a shared library — its entropy '
        'source was not confirmed from strings analysis alone. '
        'Two possibilities: '
        '(1) Rng wraps /dev/urandom — SAFE. '
        '(2) Rng wraps a PRNG seeded from time (srand pattern as in user daemon, '
        '    MTIK-USER-F04) — DANGEROUS for PKEX private key generation. '
        'If getDefaultRng() calls getDefaultRng → time-seeded srand, the PKEX private '
        'bootstrap key is derivable from device boot time (~2^27 candidates as in user daemon). '
        'Bootstrap key compromise allows PKEX session key recovery.'
    ),
    'usage': 'randomBigNum used in PKEX key generation (authDeriveZ input) and certificate key generation',
}

# ---------------------------------------------------------------------------
# nv→m3 message bridge
# ---------------------------------------------------------------------------

NV_M3_BRIDGE = {
    'flatten_sym': '_ZN2nv12flat_message9m3flattenE4spanIKhEPN2m37messageE',
    'sig':         'static void nv::flat_message::m3flatten(span<uint8_t const>, m3::message*)',
    'role': (
        'Converts a serialized nv:: flat message wire format into an m3::message object. '
        'figman bridges both IPC systems: it receives m3:: messages from peers over sockets '
        '(ConnImpl::recvMsg) and interacts with Nova store via nv:: messages. '
        'The bridge function takes raw bytes (span) and writes into an m3::message. '
        'If the span contains malformed nv::flat_message encoding (wrong field lengths, '
        'malformed type tags), the conversion may write out-of-bounds into the m3::message '
        'internal buffer — depending on m3::message::put bounds checking.'
    ),
    'confusion_risk': (
        'Format confusion: a peer that sends an m3::message crafted to look like a valid '
        'nv::flat_message could trigger m3flatten on data that is not actually a flat_message. '
        'The distinguishing check (if any) between the two formats is not visible in figman''s '
        'PLT or strings.'
    ),
}

# ---------------------------------------------------------------------------
# Package download TOCTOU
# ---------------------------------------------------------------------------

PACKAGE_DOWNLOAD = {
    'paths': {
        'staging':  '/rw/pckg/.download/',
        'ignore':   '/rw/pckg/.download/IGNORE',
        'lock':     '/rw/pckg/.download/LOCK',
    },
    'pattern': (
        'figman creates or checks /rw/pckg/.download/LOCK before operating on the '
        'staging directory. LOCK is an advisory lock implemented as a file — a '
        'check-then-act pattern. '
        'Race window: '
        '(1) figman checks LOCK existence (stat/open); '
        '(2) another process creates LOCK and writes to staging; '
        '(3) figman proceeds assuming it holds the lock. '
        'In RouterOS, the Nova bus and multiple daemons can trigger package operations '
        'concurrently. A TOCTOU race here could corrupt the staging directory or cause '
        'figman to install a partially written package.'
    ),
    'writable_by': '/rw/ is writable at runtime (rw partition)',
}

# ---------------------------------------------------------------------------
# AES-SIV and HKDF
# ---------------------------------------------------------------------------

CRYPTO_SAFE = {
    'aes_siv': {
        'encrypt_sym': '_ZN6AESSIV7encryptERK4spanIKhERK6vectorIS2_EPh',
        'decrypt_sym': '_ZN6AESSIV7decryptERK4spanIKhERK6vectorIS2_EPh',
        'note': (
            'AES-SIV (Synthetic IV) is an authenticated encryption mode providing '
            'misuse resistance — safe even if nonce is reused, unlike AES-GCM. '
            'Error strings ": AES-SIV encrypt failed" and ": AES-SIV decrypt failed" '
            'indicate error paths are handled (not silently ignored). CLEAN.'
        ),
    },
    'hkdf': {
        'sym': '_Z5HKPDFR4HashRK6vectorIhES4_S4_j',
        'sig': 'HKDF(Hash&, vector<uint8_t> ikm, vector<uint8_t> salt, vector<uint8_t> info, uint outlen)',
        'note': 'Standard HKDF construction. CLEAN.',
    },
    'hmac': {
        'sym': '_ZN4HMACC2EP4HashPKvj',
        'note': 'HMAC constructor: HMAC(Hash*, void const* key, uint keylen). Standard HMAC. CLEAN.',
    },
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

FINDINGS = [
    {
        'id':       'MTIK-FIGMAN-F01',
        'severity': 'HIGH',
        'cvss':     7.5,
        'title':    'WCurve::mul timing side-channel — custom Weierstrass scalar mul; constant-time status unknown',
        'detail': (
            'figman implements PKEX (Wi-Fi Easy Connect / DPP) using a custom Weierstrass '
            'elliptic curve (WCurve). The scalar multiplication WCurve::mul(scalar, Point) '
            'is the core operation in PKEXImpl::authDeriveZ, which derives the PKEX '
            'shared secret Z from the local private key and the peer''s public point. '
            'WCurve uses a MontgomeryReducer for modular arithmetic, but Montgomery form '
            'alone does not guarantee constant-time execution — the scalar loop must also '
            'avoid conditional branches on secret bits (e.g., via Montgomery ladder or '
            'double-and-always-add). '
            'No evidence of a constant-time ladder was found: '
            '  - No branchless select pattern in exported WCurve symbols '
            '  - Standard Weierstrass add vs. double distinction (two separate functions: '
            '    mul and add) suggests a conditional dispatch based on the point identity '
            '    check, which is the defining feature of a variable-time implementation '
            'If WCurve::mul is variable-time, a PKEX initiator (attacker who triggers '
            'PKEXConsole or PKEXPushButton enrollment) can measure the wall-clock duration '
            'of authDeriveZ over many sessions and recover the device bootstrap private key '
            'via a Kocher-class timing attack. '
            'Bootstrap key compromise allows: '
            '(1) Forging PKEX enrollment of rogue APs '
            '(2) Decrypting past PKEX sessions if session keys were derived from the bootstrap key '
            '(3) Impersonating the router in CAPsMAN AP enrollment'
        ),
        'evidence': {
            'mul_sym':         '_ZNK6WCurve3mulERK6BigNumRKNS_5PointE',
            'add_sym':         '_ZNK6WCurve3addERNS_5PointERKS0_P6RedNum',
            'montgomery':      '_ZN17MontgomeryReducerC1ERK6BigNum (present)',
            'authDeriveZ_sym': 'bool PKEXImpl::authDeriveZ(BigNum const&, BigNum const&)',
            'constant_time':   'NOT CONFIRMED — no ladder symbol, two-function mul/add pattern',
            'validation':      'isOnCurve present — correct but insufficient to prevent timing',
        },
        'recommendation': (
            'Audit WCurve::mul source for constant-time scalar multiplication. '
            'Replace with a Montgomery ladder implementation: '
            '  R[0] = point; R[1] = 2*point; '
            '  for bit k in scalar from MSB: R[1-bit] = R[0] + R[1]; R[bit] = 2*R[bit]; '
            'Use a branchless conditional select (e.g., WCurve::condSwap) instead of '
            'if-branches on the secret scalar. '
            'Consider replacing WCurve with a standard constant-time library '
            '(e.g., libsodium crypto_scalarmult or OpenSSL EC_POINT_mul with BN_FLG_CONSTTIME).'
        ),
        'status': 'UNCONFIRMED — requires WCurve::mul source or binary timing measurement',
        'cve': None,
    },
    {
        'id':       'MTIK-FIGMAN-F02',
        'severity': 'HIGH',
        'cvss':     7.2,
        'title':    'eddsa::get_public_key(asn1::blob) — ASN.1 DER parsing of attacker-supplied blob',
        'detail': (
            'eddsa::get_public_key(asn1::blob) parses an ASN.1 DER blob to extract an '
            'Ed25519 public key. The blob is passed as a value (span-like asn1::blob type). '
            'Attack surfaces that can supply a crafted blob: '
            '(1) PKEX peer certificate — during PKEXImpl enrollment, the peer sends its '
            '    bootstrap certificate; figman calls get_public_key on the peer cert blob. '
            '(2) CMR upgrade (cmr::Upgr::init) — certificate from Nova message. '
            '(3) Nova store /nova/store/figman/peer — peer cert stored in Nova; any '
            '    authenticated Nova bus participant can write a crafted cert. '
            'ASN.1 DER parsing vulnerabilities: '
            '  - Tag-length overflow: length field > remaining bytes → OOB read '
            '  - High-bit length: 0x84 = "4-byte length follows"; if not checked → OOB '
            '  - Constructed Ed25519 key encoding: standard prohibits constructed, '
            '    but a tolerant parser accepting it may read additional data '
            '  - Zero-length BIT STRING: OOB if code subtracts unused-bits byte count '
            '    before checking length. '
            'The DER parser implementation is in figman itself or a shared library '
            '(DerEncoder class present; decoder not separately named but likely paired). '
            'If the parser lacks one of these checks, a crafted certificate causes a '
            'heap OOB read or overflow in figman (running as root).'
        ),
        'evidence': {
            'get_public_key': '_ZN5eddsa14get_public_keyEN4asn14blobE',
            'private_init':   '_ZN17Ed25519PrivateKey11initPrivateE6vectorIhE',
            'readCertFromStr': '_Z15readCertFromStr11string_view',
            'DerEncoder':     'present — _ZN10DerEncoder6addTagEjj, _ZN10DerEncoder9updateLenEj',
            'peer_cert_error': '"no peer certificate" / "failed to parse peer certificate" strings',
            'attack_vector':  'PKEX enrollment, CMR upgrade, Nova store figman/peer',
        },
        'recommendation': (
            'Fuzz get_public_key and readCertFromStr with malformed DER input: '
            'zero-length BIT STRING, truncated length octets, indefinite-length encoding, '
            'negative-length values, unexpected constructed encoding for primitive types. '
            'Pre-validate blob.len() > minimum DER structure size before parsing. '
            'Ensure the parser is length-checked at every tag/length boundary.'
        ),
        'status': 'UNCONFIRMED — requires DER parser source or fuzzing',
        'cve': None,
    },
    {
        'id':       'MTIK-FIGMAN-F03',
        'severity': 'MEDIUM',
        'cvss':     6.1,
        'title':    'getDefaultRng() entropy source unknown — randomBigNum key material potentially weak',
        'detail': (
            'getDefaultRng() provides the Rng object used in all randomBigNum calls. '
            'randomBigNum(BigNum*, BigNum const& max, Rng const&) generates random BigNums '
            'for PKEX private key material and certificate key generation. '
            'The Rng class is not directly analyzable from figman''s PLT — it is either '
            'inline or in a shared library with no exported Rng symbols visible. '
            'If getDefaultRng() wraps rand() (time-seeded srand pattern observed in '
            'routeros_user_daemon_re.py / MTIK-USER-F04), the PKEX bootstrap private key '
            'is generated from ~2^27 candidates, fully recoverable in hours on commodity hardware. '
            'The user daemon (user) and figman (figman) are separate processes but may share '
            'the same libcrypto or internal RNG library. If the same srand(tv_sec + tv_usec) '
            'seeding is used, key material across both daemons correlates with boot time.'
        ),
        'evidence': {
            'getDefaultRng_sym': '_Z13getDefaultRngv',
            'randomBigNum_sym':  '_Z12randomBigNumP6BigNumRKS_RK3Rng',
            'Rng_class':         'No exported Rng symbols — entropy source unconfirmed',
            'related_finding':   'MTIK-USER-F04 (srand time seed in user daemon)',
        },
        'recommendation': (
            'Confirm getDefaultRng() entropy source: if it wraps rand(), replace with '
            'a /dev/urandom-backed CSPRNG. '
            'Audit all randomBigNum call sites to identify which keys are generated with '
            'the default Rng vs. an explicitly passed secure Rng. '
            'Cross-reference with MTIK-USER-F04 — if both daemons share the srand pattern, '
            'the scope of weak key material is broader than a single daemon.'
        ),
        'status': 'UNCONFIRMED — Rng implementation needs source or binary trace',
        'cve': None,
    },
    {
        'id':       'MTIK-FIGMAN-F04',
        'severity': 'MEDIUM',
        'cvss':     5.9,
        'title':    'nv::flat_message::m3flatten — format confusion between nv:: and m3:: wire formats',
        'detail': (
            'nv::flat_message::m3flatten(span<uint8_t const>, m3::message*) converts raw '
            'bytes from the nv:: flat message wire format into an m3::message object. '
            'figman bridges both IPC systems: inbound connections use m3:: format '
            '(ConnImpl::recvMsg → m3::message::read), while Nova store interactions use nv::. '
            'The bridge function takes an untyped span<uint8_t const> and writes into '
            'm3::message. Two format confusion risks: '
            '(1) If a peer (over socket) sends bytes structured as an m3:: message but '
            'the receive path incorrectly calls m3flatten (treating it as a nv::flat_message), '
            'the m3 parser will misinterpret field boundaries. With no shared magic byte or '
            'length prefix discrimination visible in strings, the format selection may be '
            'connection-context-only — creating a state machine confusion attack. '
            '(2) m3flatten output (m3::message*) is used by subsequent m3::message::read '
            'and m3::filterMsg calls. If m3flatten writes malformed m3 field tags, '
            'filterMsg may access out-of-bounds fields on the m3::message internal buffer.'
        ),
        'evidence': {
            'flatten_sym': '_ZN2nv12flat_message9m3flattenE4spanIKhEPN2m37messageE',
            'filterMsg':   '_ZN2m39filterMsgERNS_7messageERK6vectorIjE',
            'both_formats': 'Both m3::fromraw32 and nv::flat_message present in same binary',
        },
        'recommendation': (
            'Add a discriminator byte or magic prefix to distinguish nv::flat_message from '
            'm3::message wire format before calling m3flatten. '
            'Ensure m3::message::put bounds-checks all field writes from m3flatten output. '
            'Add assertion that m3flatten output message is valid before filterMsg call.'
        ),
        'status': 'UNCONFIRMED — requires message-dispatch flow trace',
        'cve': None,
    },
    {
        'id':       'MTIK-FIGMAN-F05',
        'severity': 'LOW',
        'cvss':     4.3,
        'title':    '/rw/pckg/.download/LOCK — TOCTOU race on package download staging',
        'detail': (
            '/rw/pckg/.download/LOCK is an advisory lock file used to serialize package '
            'download operations in /rw/pckg/.download/. '
            'figman checks LOCK existence before writing to the staging directory. '
            'Check-then-act race: '
            '(1) figman: stat("/rw/pckg/.download/LOCK") → not present '
            '(2) [race window] another process creates LOCK and writes malformed package data '
            '    to /rw/pckg/.download/<name>.npk '
            '(3) figman: proceeds to open/read the staging directory assuming exclusive access '
            'If figman reads and processes the malformed .npk (e.g., passes it to the NPK '
            'installer), this chains with NPK installer vulnerabilities (MTIK-NPKINST-F01). '
            '/rw/ is writable at runtime; exploiting this race requires a second process '
            'with write access to /rw/pckg/.download/ (e.g., another compromised daemon).'
        ),
        'evidence': {
            'lock_path':   '/rw/pckg/.download/LOCK',
            'ignore_path': '/rw/pckg/.download/IGNORE',
            'writable_at': '/rw/ (rw partition, writable at runtime)',
            'chains_with': 'MTIK-NPKINST-F01 (NPK installer path traversal)',
        },
        'recommendation': (
            'Replace advisory LOCK file with an O_EXCL-based atomic lock: '
            'open("/rw/pckg/.download/LOCK", O_CREAT|O_EXCL|O_WRONLY, 0600) '
            'creates the lock atomically — eliminates TOCTOU. '
            'On failure (EEXIST), spin with nanosleep or return error. '
            'Ensure lock is unlinked (not just closed) on exit to prevent stale locks.'
        ),
        'status': 'UNCONFIRMED — requires confirmation that figman reads staging dir after LOCK check',
        'cve': None,
    },
    {
        'id':       'MTIK-FIGMAN-F06',
        'severity': 'INFO',
        'cvss':     0.0,
        'title':    'AES-SIV authenticated encryption — standard algorithm, error path handled — CLEAN',
        'detail': (
            'AESSIV::encrypt and AESSIV::decrypt are authenticated encryption operations. '
            'AES-SIV provides nonce-misuse resistance: ciphertext authentication is '
            'computed as CMAC over the plaintext, then used as the SIV nonce. '
            'Error strings ": AES-SIV encrypt failed" and ": AES-SIV decrypt failed" '
            'confirm that encrypt/decrypt failures are detected and reported, not silently '
            'ignored. No custom modifications to the AES-SIV construction were identified. '
            'CLEAN.'
        ),
        'evidence': {
            'encrypt_sym': '_ZN6AESSIV7encryptERK4spanIKhERK6vectorIS2_EPh',
            'decrypt_sym': '_ZN6AESSIV7decryptERK4spanIKhERK6vectorIS2_EPh',
            'error_strings': [': AES-SIV encrypt failed', ': AES-SIV decrypt failed'],
        },
        'recommendation': 'No action required.',
        'status': 'CLEAN',
        'cve': None,
    },
    {
        'id':       'MTIK-FIGMAN-F07',
        'severity': 'INFO',
        'cvss':     0.0,
        'title':    'HKDF and HMAC — standard KDF/MAC primitives — CLEAN',
        'detail': (
            'HKDF(Hash&, ikm, salt, info, outlen) is a standard key derivation function '
            'per RFC 5869. HMAC is a standard message authentication code. '
            'Both are used in figman for key derivation during PKEX and certificate operations. '
            'No custom modifications identified. CLEAN.'
        ),
        'evidence': {
            'hkdf_sym': '_Z5HKPDFR4HashRK6vectorIhES4_S4_j',
            'hmac_sym':  '_ZN4HMACC2EP4HashPKvj',
        },
        'recommendation': 'No action required.',
        'status': 'CLEAN',
        'cve': None,
    },
]
