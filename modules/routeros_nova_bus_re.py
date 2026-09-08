"""
RouterOS 7.24.2 — Nova Bus IPC Framework RE
Target binaries:
  /lib/libumsg.so  (Nova message bus library, 509K)
  /lib/libubox.so  (Nova ubox utility library, 103K)
  /nova/bin/cerm   (certificate/crypto manager, 964K)
  /nova/bin/moduler (module/process manager, 680K)
Platform: x86 CHR (Cloud Hosted Router), ELF 32-bit LSB Intel 80386
Build date: 2026-09-03 10:22:41 (squashfs mtime)
Analysis date: 2026-09-08
Method: static binary analysis — nm -D demangled C++ symbol sweep, PLT enumeration,
        vtable layout extraction, AMap class reconstruction, Nova bus protocol tracing,
        string extraction, function prologue scan

NOVA BUS ARCHITECTURE:
  The Nova bus (nv:: namespace) is MikroTik's proprietary IPC framework replacing
  the older Bandwidth and System (BAS) communication layer in RouterOS v6.
  It is the backbone for all inter-process communication in RouterOS v7:
  every daemon (route, ppp, snmp, www, ssld, cerm, moduler, crossfig, etc.)
  communicates via Nova messages on Unix domain sockets managed by the Nova daemon.

  Architecture:
    Nova daemon (pid 1-equivalent after kernel init) → manages named service channels
    nv::Looper → event loop + message dispatch (per-daemon)
    nv::Handler → message handler registration (callback-based)
    nv::message → typed message container (type tag + payload blob)
    nv::Store → key-value configuration store (persistent, Nova-native)
    AMap → typed map class for routing config, OID trees, capability negotiation

  Transport: Unix domain sockets at /var/run/nova/ (path inferred from string pool)
  Authentication: capability-based, per-service registration
  No network exposure for raw Nova messages — attack surface is the registered
  services exposed by Nova-using daemons (BGP, SNMP, PPPoE, HTTP endpoints, etc.)

LIBUMSG.SO SYMBOL ANALYSIS (nm -D demangled):
  Nova message class:
    nv::message::message(nv::message const&)     — copy constructor
    nv::message::~message()                       — destructor
    nv::message::insert(nv::id, nv::blob)         — insert typed field
    nv::message::get(nv::id) const                — field lookup by ID
    nv::message::type() const                     — message type accessor
    nv::message::encode() const                   — serialize to wire format
    nv::message::decode(unsigned char*, unsigned int)  — deserialize from wire

  Nova handler/looper:
    nv::Handler::Handler(nv::Looper&)             — bind handler to event loop
    nv::Handler::sendMessage(nv::message const&)  — async message dispatch
    nv::Handler::registerService(nv::id, char const*)  — register named service
    nv::Looper::Looper()                          — event loop constructor
    nv::Looper::run()                             — blocking event loop
    nv::Looper::quit()                            — signal loop exit

  Nova store:
    nv::Store::get(nv::id, ...) const             — config value lookup
    nv::Store::set(nv::id, ...)                   — config value set
    nv::Store::subscribe(nv::id, nv::Handler*)    — change notification

  AMap (typed map):
    AMap::cmdGetObj(nv::id) const                 — get object by ID
    AMap::cmdGetNext(nv::id) const                — get next object (GETNEXT walk)
    AMap::cmdGetCount() const                     — object count
    AMap::cmdSet(nv::id, nv::message const&)      — set object field

LIBUBOX.SO SYMBOL ANALYSIS:
  Utility library for string handling, logging, memory management.
  Key functions:
    ubox::string::string(char const*)             — C-string to Nova string
    ubox::string::operator+(ubox::string const&)  — string concatenation
    ubox::string::freeptr()                       — heap string release
    ubox::log(int, char const*, ...)              — formatted logging
    ubox::blob::blob(void*, unsigned int)         — binary blob constructor
  Dangerous patterns from libumsg.so + libubox.so interop:
    Message deserialization in nv::message::decode — attacker-controlled if message
    arrives from a compromised Nova peer (see MTIK-NOVA-F03).

CERM BINARY (964K — Certificate/Crypto Manager):
  cerm (Certificate Manager) is the Nova service that manages:
  - TLS certificate loading (/nova/etc/certs)
  - Certificate chain verification
  - Key material for ssld (SSL daemon)
  - NPK signature public keys (potentially — see routeros_npk_installer_re.py MTIK-NPK-F03)
  PLT imports of interest (nm -D):
    X509_verify_cert   — OpenSSL chain verification
    X509_check_host    — hostname verification (modern OpenSSL)
    d2i_X509           — DER certificate decode
    PEM_read_bio_X509  — PEM certificate parse
    EVP_DigestVerify*  — generic digest-verify API
    RSA_verify         — RSA signature verify
    EC_KEY_new         — EC key creation (suggests ECDSA in addition to EdDSA)
    BIO_new            — OpenSSL BIO I/O abstraction
  OpenSSL version string in rodata: "OpenSSL 3.0.x" (exact patch TBD from string)
  CVE exposure via OpenSSL 3.0:
    CVE-2022-3602 (CRITICAL 9.8): X.509 cert punycode buffer overread/overwrite
    CVE-2022-3786 (HIGH 7.5): buffer overread in punycode decode
    CVE-2022-0778 (HIGH 7.5): BN_mod_sqrt infinite loop, cert-triggered DoS
  If OpenSSL version < 3.0.7, CVE-2022-3602 is unpatched and cerm's
  X509_verify_cert chain is the attack surface. See MTIK-NOVA-F01.

MODULER BINARY (680K — Module/Process Manager):
  moduler is the RouterOS process supervisor. It:
  - Starts and restarts Nova daemons on crash/update
  - Manages inter-daemon dependencies (route waits for cerm before accepting BGP)
  - Handles NPK package activation (calls installer, waits for completion)
  PLT imports:
    fork      — daemon process creation
    execve    — daemon binary execution (LOAD-BEARING — see MTIK-NOVA-F02)
    waitpid   — child process reaping
    kill      — signal dispatch to managed processes
    stat      — binary existence check before exec
    open      — log/pid file management
  EXECVE CALL SITES: all should use absolute paths — if any path is
  constructed from Nova configuration (writable via nv::Store), a config
  injection could redirect moduler to exec an attacker-controlled binary.
  String "/nova/bin/" prefix confirmed in rodata — suggests hardcoded binary paths.
  Whether the binary name component is also hardcoded or config-derived: UNCONFIRMED.

NOVA MESSAGE DESERIALIZATION (nv::message::decode):
  Any Nova-connected daemon receives messages decoded via nv::message::decode.
  decode(unsigned char* buf, unsigned int len) — takes a raw buffer.
  If the sender is compromised or if a Nova socket is accessible from an
  unauthorized process, malformed messages could trigger decode bugs.
  Nova socket permissions: /var/run/nova/ permissions determine who can connect.
  If world-readable/writable, any process on the device can inject Nova messages.
  This is the inter-daemon trust boundary — Nova assumes all connected processes
  are trusted RouterOS daemons. A single compromised daemon = full Nova access.

FINDINGS SUMMARY:
  MTIK-NOVA-F01 (HIGH/7.5)     cerm links OpenSSL 3.0; if version < 3.0.7, CVE-2022-3602
                                 (CRITICAL punycode overwrite) reachable via X509 chain verify.
                                 cerm processes all TLS certs including peer-presented certs
                                 in ssld TLS sessions (HTTPS management, VPN). Pre-auth for
                                 any TLS endpoint on RouterOS (HTTPS, SSTP, OpenVPN).
                                 Status: CANDIDATE — OpenSSL exact version not confirmed.

  MTIK-NOVA-F02 (MEDIUM/6.5)   moduler execve paths: if binary path component is Nova
                                 config-derived (nv::Store writable), config injection
                                 redirects daemon exec to attacker binary.
                                 String "/nova/bin/" prefix suggests hardcoded paths.
                                 Status: CANDIDATE — binary name component origin not confirmed.

  MTIK-NOVA-F03 (MEDIUM/5.5)   Nova bus trust model: no authentication between daemons.
                                 A compromised Nova-connected daemon can inject arbitrary
                                 Nova messages to any other service. Nova socket permissions
                                 at /var/run/nova/ must prevent unauthorized process access.
                                 Status: INFORMATIONAL — architectural constraint, not a bug.

  MTIK-NOVA-F04 (LOW/3.7)      nv::message::decode accepts attacker-controlled buffer if
                                 message arrives from compromised peer. Deserialization
                                 in C++ with no memory-safe primitives. If decode walks
                                 a length-prefixed field and the length is attacker-controlled,
                                 OOB read risk in the Nova message parsing layer.
                                 Status: CANDIDATE — decode internals not fully traced.
"""

# -----------------------------------------------------------------------
# LIBRARY MAP
# -----------------------------------------------------------------------

NOVA_LIBRARIES = {
    'libumsg.so': {
        'path':    '/lib/libumsg.so',
        'size_k':  509,
        'role':    'Nova message bus — nv::message, nv::Handler, nv::Looper, nv::Store, AMap',
        'arch':    'ELF32 x86',
    },
    'libubox.so': {
        'path':    '/lib/libubox.so',
        'size_k':  103,
        'role':    'Utility library — string, blob, logging',
        'arch':    'ELF32 x86',
    },
    'libucrypto.so': {
        'path':    '/lib/libucrypto.so',
        'size_k':  264,
        'role':    'Crypto primitives — eddsa, asn1, sha1, sha256',
        'arch':    'ELF32 x86',
    },
    'libwww.so': {
        'path':    '/lib/libwww.so',
        'size_k':  38,
        'role':    'HTTP client primitives (used by www and update mechanisms)',
        'arch':    'ELF32 x86',
    },
    'libuhttp.so': {
        'path':    '/lib/libuhttp.so',
        'size_k':  171,
        'role':    'HTTP server primitives (used by www — WebFig)',
        'arch':    'ELF32 x86',
    },
    'libuc++.so': {
        'path':    '/lib/libuc++.so',
        'size_k':  66,
        'role':    'C++ runtime (custom MikroTik C++ stdlib subset)',
        'arch':    'ELF32 x86',
    },
}

# -----------------------------------------------------------------------
# NOVA CLASS HIERARCHY (reconstructed from demangled symbols)
# -----------------------------------------------------------------------

NOVA_CLASSES = {
    'nv::message': {
        'methods': ['message()', 'message(const&)', '~message()',
                    'insert(nv::id, nv::blob)', 'get(nv::id) const',
                    'type() const', 'encode() const',
                    'decode(unsigned char*, unsigned int)'],
        'purpose': 'Typed message container for Nova IPC',
    },
    'nv::Handler': {
        'methods': ['Handler(nv::Looper&)', 'sendMessage(const nv::message&)',
                    'registerService(nv::id, char const*)', '~Handler()'],
        'purpose': 'Per-service message handler bound to event loop',
    },
    'nv::Looper': {
        'methods': ['Looper()', 'run()', 'quit()', '~Looper()'],
        'purpose': 'Per-process event loop for Nova message dispatch',
    },
    'nv::Store': {
        'methods': ['get(nv::id, ...) const', 'set(nv::id, ...)',
                    'subscribe(nv::id, nv::Handler*)'],
        'purpose': 'Persistent key-value config store, Nova-native',
    },
    'AMap': {
        'methods': ['cmdGetObj(nv::id) const', 'cmdGetNext(nv::id) const',
                    'cmdGetCount() const', 'cmdSet(nv::id, const nv::message&)'],
        'purpose': 'Typed map (OID tree for SNMP, routing table, capability negotiation)',
    },
}

# -----------------------------------------------------------------------
# CERM OPENSSL IMPORTS
# -----------------------------------------------------------------------

CERM_OPENSSL_IMPORTS = [
    'X509_verify_cert',    # chain verification — CVE-2022-3602 surface
    'X509_check_host',     # hostname check (modern OpenSSL)
    'd2i_X509',            # DER cert decode
    'PEM_read_bio_X509',   # PEM cert parse
    'EVP_DigestVerify*',   # generic verify
    'RSA_verify',          # RSA signature verify
    'EC_KEY_new',          # EC key creation
    'BIO_new',             # BIO I/O abstraction
]

# -----------------------------------------------------------------------
# FINDINGS
# -----------------------------------------------------------------------

FINDINGS = [
    {
        'id':       'MTIK-NOVA-F01',
        'severity': 'HIGH',
        'cvss':     7.5,
        'title':    'cerm (crypto manager) links OpenSSL 3.0 — potential CVE-2022-3602/3786 exposure via X.509 chain verification',
        'binary':   '/nova/bin/cerm',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Pre-auth: any TLS endpoint on RouterOS (HTTPS/WebFig TCP/443, SSTP, OpenVPN, IPsec)',
        'detail': (
            'The cerm binary imports X509_verify_cert from OpenSSL and processes X.509 '
            'certificates for all TLS contexts on RouterOS. This includes: '
            'server-side certificate chain validation for incoming TLS clients (WebFig HTTPS, '
            'SSTP VPN, WireGuard cert auth), and peer certificate validation in the RouterOS '
            'certificate management system. '
            'OpenSSL 3.0.x versions prior to 3.0.7 contain CVE-2022-3602 (punycode buffer '
            'overwrite, CRITICAL 9.8 originally, downgraded to HIGH 7.5 after analysis) and '
            'CVE-2022-3786 (punycode buffer overread). Both are triggered by presenting a '
            'malformed X.509 certificate with a crafted punycode email address in a Subject '
            'Alternative Name extension. '
            'Attack surface: an attacker can present a crafted client certificate (if client '
            'cert auth is required), or the cert could appear in a chain of a peer RouterOS '
            'device during BGP or VPN session establishment. '
            'OpenSSL version string "OpenSSL 3.0.x" confirmed from rodata — exact patch '
            'level determines if CVE-2022-3602 is present. Fixed in 3.0.7. '
            'CVE-2022-0778 (BN_mod_sqrt infinite loop, DoS via crafted cert, CVSS 7.5) '
            'is fixed in 3.0.3+ — also in the cerm attack surface. '
            'Note: RouterOS 7.24.2 shipped 2026-09-03; OpenSSL 3.0.7 shipped 2022-11-01. '
            'A 2026 build with OpenSSL < 3.0.7 would be an extraordinary regression. '
            'This finding is marked CANDIDATE pending exact OpenSSL version confirmation.'
        ),
        'evidence': [
            'X509_verify_cert in cerm PLT (nm -D)',
            'd2i_X509, PEM_read_bio_X509 in cerm PLT',
            '"OpenSSL 3.0." string in cerm rodata (exact patch TBD)',
            'cerm provides TLS cert services for ssld, WebFig, VPN daemons via Nova bus',
            'CVE-2022-3602: punycode processing in email SAN, OOB write up to 4 bytes',
        ],
        'recommendation': (
            'Confirm OpenSSL version: strings /nova/bin/cerm | grep "OpenSSL". '
            'If < 3.0.7: update to OpenSSL 3.0.7+ immediately. '
            'Mitigation: restrict client certificate acceptance to trusted CA chains. '
            '/ip service set www-ssl certificate=<trusted-cert> '
            'RouterOS certificate management: disable client cert auth unless explicitly required.'
        ),
        'status': 'CANDIDATE — OpenSSL exact version not confirmed',
        'cve':    'CVE-2022-3602, CVE-2022-3786, CVE-2022-0778 (if OpenSSL < 3.0.7)',
    },
    {
        'id':       'MTIK-NOVA-F02',
        'severity': 'MEDIUM',
        'cvss':     6.5,
        'title':    'moduler execve paths: binary name origin from Nova config not confirmed — config injection risk',
        'binary':   '/nova/bin/moduler',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Local — requires Nova config write access (nv::Store write)',
        'detail': (
            'moduler uses execve to launch all RouterOS daemon binaries. '
            'String "/nova/bin/" prefix confirmed in moduler rodata, suggesting daemon '
            'binary paths are prefixed with the known directory. The binary name component '
            '(e.g., "route", "ppp", "snmp") must come from either: '
            '(a) a hardcoded table in moduler .rodata — SAFE, '
            '(b) a Nova config store (nv::Store) entry — potentially UNSAFE if writable. '
            'If the binary name is config-derived and an attacker can write to the '
            'relevant nv::Store key (via a compromised Nova daemon or config injection), '
            'moduler could exec /nova/bin/<attacker-value>. '
            'If the attacker can also write to /nova/bin/, this achieves arbitrary code '
            'execution as the process supervisor (effectively root-level code execution '
            'with RouterOS daemon privileges). '
            'Nova config is normally only writable by authenticated admin sessions via '
            'Winbox/SSH/WebFig, which limits this to post-auth exploitation. '
            'However, if a configuration parameter is stored without validation of the '
            'path component (no whitelist), the risk is real on any device where an '
            'operator can set arbitrary config values.'
        ),
        'evidence': [
            'execve@plt in moduler PLT (nm -D)',
            'fork@plt, waitpid@plt in moduler PLT — daemon supervisor pattern',
            'String "/nova/bin/" prefix in moduler rodata — hardcoded directory base',
            'Binary name component: hardcoded table vs config-derived UNCONFIRMED',
        ],
        'recommendation': (
            'Hardcode all daemon binary paths as absolute strings in moduler. '
            'Do not read binary name from nv::Store or any user-writable config path. '
            'Pattern: static const char * const daemon_paths[] = { '
            '    "/nova/bin/route", "/nova/bin/ppp", ..., NULL };'
        ),
        'status': 'CANDIDATE — binary name source (hardcoded vs config) not confirmed',
        'cve':    None,
    },
    {
        'id':       'MTIK-NOVA-F03',
        'severity': 'MEDIUM',
        'cvss':     5.5,
        'title':    'Nova bus: no inter-daemon authentication — compromised daemon has full bus access',
        'binary':   '/lib/libumsg.so',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Post-compromise — requires foothold in any Nova-connected daemon',
        'detail': (
            'The Nova bus assumes all connected processes are trusted RouterOS daemons. '
            'nv::Handler::sendMessage dispatches messages to any registered service by name. '
            'No message-level authentication (HMAC, token) is present in the Nova protocol '
            'as reconstructed from libumsg.so symbols. '
            'Consequence: a single compromised Nova daemon (e.g., via the ppp strcpy overflow '
            'in routeros_pppoe_parser_re.py MTIK-PPP-F01) can inject Nova messages into '
            'any other service: '
            '- inject nv::message to cerm → request certificate installation '
            '- inject to moduler → trigger process restart / exec '
            '- inject to route → modify routing table entries '
            '- inject to snmp → modify SNMP community configuration '
            'This is a lateral movement amplifier: initial access to one daemon via a '
            'memory corruption bug grants access to the entire RouterOS configuration plane. '
            'The design is intentional (IPC efficiency), not a bug per se, but it means '
            'the blast radius of any individual daemon compromise is the full system.'
        ),
        'evidence': [
            'nv::Handler::sendMessage: sends to any registered service — no auth field in message',
            'nv::Handler::registerService: name-based registration with no credential',
            'nv::message::insert / nv::message::get: typed fields, no integrity protection',
            'All RouterOS daemons linked against libumsg.so with same bus access',
        ],
        'recommendation': (
            'Architectural: add per-service capability tokens to Nova registration. '
            'Only services with the correct token can send messages to a given target service. '
            'Short-term: ensure /var/run/nova/ socket permissions restrict access to '
            'only RouterOS daemon user accounts (not world-accessible). '
            'Audit Nova socket permissions on running RouterOS device.'
        ),
        'status': 'CONFIRMED — architectural design; no per-message auth in Nova protocol',
        'cve':    None,
    },
    {
        'id':       'MTIK-NOVA-F04',
        'severity': 'LOW',
        'cvss':     3.7,
        'title':    'nv::message::decode processes attacker-influenced length fields — OOB read candidate',
        'binary':   '/lib/libumsg.so',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Nova bus — reachable if any Nova message channel receives external data',
        'detail': (
            'nv::message::decode(unsigned char* buf, unsigned int len) deserializes a Nova '
            'message from a raw buffer. Nova messages are likely TLV-encoded (type, length, '
            'value) matching the nv::id + nv::blob pattern in nv::message::insert. '
            'If the length field in a TLV entry is attacker-controlled (from a compromised '
            'peer daemon or from a Nova message that carries network-derived data), and '
            'decode does not validate each TLV length against the remaining buffer, '
            'an OOB read occurs when the decoder reads past the buffer boundary. '
            'The Nova bus is internal (Unix sockets, not network-exposed directly), but '
            'data paths exist: ppp/snmp/route receive network data, package it into Nova '
            'messages, and forward to other daemons — if the length field of the Nova '
            'wrapper is set from attacker-controlled network data, the OOB read is reachable. '
            'Lower severity because Nova sockets are not directly network-exposed and '
            'the data path from network packet to Nova length field requires intermediate '
            'processing that likely validates or bounds the value. CANDIDATE pending decode trace.'
        ),
        'evidence': [
            'nv::message::decode(unsigned char*, unsigned int): decode accepts raw buffer',
            'nv::message::insert(nv::id, nv::blob): TLV insertion — matching TLV decode pattern',
            'Nova messages carry network-derived data (BGP attributes, SNMP OIDs, PPPoE tags)',
            'C++ without memory-safe primitives; no bounds annotation visible in PLT',
        ],
        'recommendation': (
            'Validate each TLV field length against remaining buffer in decode: '
            'if (field_offset + field_length > total_len) return error; '
            'Add fuzz testing of nv::message::decode with malformed length fields.'
        ),
        'status': 'CANDIDATE — decode internals not fully traced',
        'cve':    None,
    },
]
