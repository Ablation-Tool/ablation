"""
Cisco ASA lina 9.22.2.32 — QUIC inspection proxy RE
Binary: /home/cowboy/VDT/intel/cisco-downloads/asa9-22-lina/asa/bin/lina
QUIC surface not present in 9.14.2.14 or 9.16.1 (confirmed absent).
"""

MODULE_ID = "cisco_asa_quic_re"
TARGET    = "Cisco ASA lina 9.22.2.32 (x86-64, stripped)"
BASE      = "QUIC inspection proxy — new attack surface in 9.22"

# All offsets are file offsets == virtual addresses (identity-mapped LOAD segments).
# Confirmed via ELF segment parse:
#   LOAD 0: file 0x00000000  vaddr 0x00000000  sz 0x00ff8cf8
#   LOAD 1: file 0x00ff9000  vaddr 0x00ff9000  sz 0x0337f501  (.text)
#   LOAD 2: file 0x04379000  vaddr 0x04379000  sz 0x011a9d3d  (.rodata)
#   LOAD 3: file 0x05522f68  vaddr 0x05523f68  sz 0x01338210  (.data/.bss)


# ── Function inventory ────────────────────────────────────────────────────────
#
# All function name strings in .rodata cross-referenced to .text call sites.
# snp_quic_* = Snort/datapath QUIC layer
# quic_trk_* = QUIC handshake tracker (TLS interception layer)
# quic_decode_* = QUIC packet header parser
#
FUNCTION_INVENTORY = {
    # Parser layer
    'quic_decode_hd_long':              0x01589990,  # long-header parser (INITIAL/HS/0RTT/RETRY)
    'quic_decode_hd_short':             None,         # short-header parser (1-RTT app data)
    'quic_decode_decrypted_packet':     None,         # post-decrypt frame parser
    'quic_decode_decrypted_pkt_new':    None,         # revised version (string: quic_decode_decrypted_pkt)
    'quic_parse_crypto_cframe':         None,
    'quic_parse_crypto_cframe_new':     None,
    'quic_parse_ack_cframe':            None,
    'quic_parse_connection_close_cframe': None,

    # Crypto layer
    'snp_quic_crypt_decrypt':           None,
    'snp_quic_crypt_encrypt':           None,
    'snp_quic_crypt_get_mask':          None,         # header protection mask
    'snp_quic_trk_decrypt':             None,
    'snp_quic_trk_encrypt':             None,
    'snp_quic_trk_decrypt_try':         None,         # pre-key-establishment attempt
    'snp_quic_trk_encrypt_try':         None,
    'snp_quic_trk_decrypt_header':      None,
    'snp_quic_trk_encrypt_header':      None,
    'snp_quic_trk_decrypt_cb':          None,         # handshake decrypt callback
    'snp_quic_trk_encrypt_cb':          None,
    'snp_quic_trk_crypt_get_mask':      None,
    'snp_quic_trk_crypt_get_mask_chacha': None,

    # Tracker / state machine
    'snp_quic_trk_alloc':               None,
    'snp_quic_trk_free':                None,
    'snp_quic_trk_proc_initial_ch':     None,         # process Client Hello
    'snp_quic_trk_proc_initial_sh':     None,         # process Server Hello
    'snp_quic_trk_process_handshake':   None,
    'snp_quic_trk_process_data':        None,
    'snp_quic_trk_process_upstream_data': None,
    'snp_quic_trk_process_downstream_data': None,
    'quic_trk_finished_verify':         0x023ffd22,   # Finished MAC verify; returns 1 on failure
    'quic_trk_switch_to_bypass':        0x0472e6b0,   # string; fn dispatch table entry
    'snp_quic_trk_set_ec_priv_key':     0x0472e670,   # string; tracker stores EC private key
    'snp_quic_trk_set_rsa_priv_key':    0x0472e690,   # string; tracker stores RSA private key

    # Proxy layer
    'snp_fp_quic_proxy':                None,         # top-level proxy dispatch
    'snp_quic_proxy_init':              None,
    'snp_quic_proxy_bypass':            0x0437b569,   # string; bypass path entry
    'snp_quic_proxy_try_decrypt':       None,
    'snp_quic_proxy_handle_decrypted_packet': None,
    'snp_quic_proxy_handle_encrypted_packet': None,
    'snp_quic_proxy_force_close_1RTT':  None,
    'snp_quic_proxy_force_close_init_hs': None,
    'snp_quic_proxy_generate_stateless_reset': None,
    'snp_quic_proxy_send_ack':          None,
    'snp_quic_proxy_process_retry_pkt': None,
    'snp_quic_proxy_encrypt_injected_pkt': None,

    # Misc
    'snp_quic_is_pkt_quic':             0x0472c7d0,   # string; initial QUIC detection
    'snp_quic_protect_against_dos_attack': 0x0472bbe0, # string; DoS protection
    'snp_quic_handle_unsupported_version_pkt': None,
    'snp_quic_send_version_negotiation_pkt': None,
    'build_quic_ack_frame':             None,
    'build_quic_connection_close_frame': None,
}

# Magic bytes used for Cisco proprietary QUIC variant identification
QUIC_CISCO_MAGIC = {
    'client_to_server': b'quiccscoH9',  # file offset 0x0233d7ad
    'server_to_client': b'cscoquicH9',  # file offset 0x0233d7c0
    'note': (
        'Cisco proprietary QUIC variant magic — used to identify Cisco-to-Cisco '
        'QUIC sessions for special proxying treatment. Presence in 9.22 lina '
        '.rodata confirms two-sided QUIC proxy capability.'
    ),
}


# ── F01: quic_decode_hd_long — long header parser analysis ───────────────────
#
# Function: 0x01589990 (PUSH RBP prologue)
# Called for INITIAL, HANDSHAKE, 0-RTT, and RETRY packets.
#
# Signature (inferred): int quic_decode_hd_long(output_t *dst, uint8_t *pkt, size_t pkt_len)
#
# Parse sequence (confirmed from disassembly):
#
#   [1] Length guard at 0x15899b3:
#       cmp $0x4, %rdx; jbe 1589f50 (error)
#       → Minimum valid packet: 5 bytes. Enforced before any field access.
#
#   [2] Version parse at 0x15899c6:
#       lea 0x1(%rsi), %rdi; call 0x158bc30
#       → 0x158bc30: memcpy(&stack_buf, &pkt[1], 4); bswap %eax
#       → Stack canary in place (fs:0x28 check at 0x158bc5b).
#       → Reads big-endian 32-bit version from bytes [1..4].
#       → Stores at output+0x48. No whitelist check here; version filtering later.
#
#   [3] DCID length at 0x1589a05:
#       movzbl 0x5(%r15), %eax   ; DCID_len = pkt[5]
#       cmp %r8, %rax            ; r8 = remaining_len - 6
#       ja 0x1589f80             ; if DCID_len > remaining: error
#
#   [4] DCID copy at 0x1589a26:
#       lea 0x28(%rbx), %rdi; call 0x158c000
#       → 0x158c000: reads length from *rdi; cmp $0x14, %rdx; ja error (-1)
#       → If length <= 20: memcpy(dst+8, src, len); return 0
#       → SPEC-REQUIRED maximum enforced in copy function.
#
#   [5] SCID length at 0x1589a57 (symmetric pattern):
#       movzbl (%r12), %eax      ; SCID_len = pkt[dcid_end]
#       cmp %r8, %rax            ; r8 = remaining_len after DCID
#       ja 0x1589fa8             ; if SCID_len > remaining: error
#       → Same 20-byte cap in 0x158c000.
#
#   [6] Token length (INITIAL only) at 0x1589ad3:
#       call 0x158bc80           ; decode VLI byte-count (1/2/4/8)
#       call 0x158bc90           ; decode VLI value
#       cmp %r8, %rax            ; token_len vs remaining
#       ja 0x158a039             ; if token_len > remaining: error
#
#   [7] Packet type dispatch at 0x1589b38:
#       movzbl 0x3(%rbx), %eax
#       cmp $0x3, %al  → je 0x1589e46  (HANDSHAKE)
#       cmp $0x80, %al → je 0x1589e46  (INITIAL flag set earlier at 0x15899da)
#
# Output struct layout (inferred from disassembly):
#   +0x00: (8B) unknown — written by caller
#   +0x03: type byte (0x80 = INITIAL set at entry; updated after version check)
#   +0x08: SCID struct {length: 8B, data[20]}
#   +0x28: DCID struct {length: 8B, data[20]}
#   +0x48: version (u32, big-endian)
#   +0x68: debug/flags
#   +0x70: token pointer (INITIAL only)
#   +0x78: payload length (decoded from VLI)
#
# Security assessment:
#   All length fields are bounds-checked before memcpy.
#   DCID/SCID max 20 enforced in the copy helper.
#   VLI token/payload length bounded against remaining bytes.
#   Stack canary on version read.
#   No buffer overflow identified in parser path.
#   Complexity concentration: 0x1589990–0x158a2xx (~0x900 bytes), 7 cross-calls.
#   Fuzzing target: malformed VLI encoding, SCID_len=20 with 0 remaining bytes.
#
QUIC_DECODE_HD_LONG = {
    'fn_va':            0x01589990,
    'length_guard':     0x015899b3,  # cmp $0x4, %rdx; jbe error
    'version_parse':    0x015899ca,  # call 0x158bc30 (memcpy+bswap)
    'dcid_len_read':    0x01589a05,  # movzbl 0x5(%r15), %eax
    'dcid_len_check':   0x01589a12,  # cmp %r8, %rax; ja 0x1589f80
    'dcid_copy_call':   0x01589a26,  # call 0x158c000 (enforces <= 20)
    'scid_len_read':    0x01589a57,  # movzbl (%r12), %eax
    'scid_len_check':   0x01589a6c,  # cmp %r8, %rax; ja 0x1589fa8
    'scid_copy_call':   0x01589a80,  # call 0x158c000
    'token_vli_count':  0x01589ad3,  # call 0x158bc80 → byte count
    'token_vli_decode': 0x01589af6,  # call 0x158bc90 → value
    'token_len_check':  0x01589ae6,  # cmp %r8, %rax; ja 0x158a039
    'type_dispatch':    0x01589b38,  # cmp $0x3; cmp $0x80
    'cid_copy_helper':  0x0158c000,  # len guard (cmp $0x14); memcpy
    'vli_bytecount_fn': 0x0158bc80,  # shr $0x6; shl → 1/2/4/8
    'version_read_fn':  0x0158bc30,  # memcpy 4 bytes + bswap
    'verdict': 'CORRECTLY_BOUNDED — no overflow in parser; all field copies length-capped',
}


# ── F02: QUIC bypass state machine ────────────────────────────────────────────
#
# Function: 0x02413e27 (main bypass propagation function)
#
# This function sets bypass mode on a QUIC tracker session and propagates it
# through all sessions in the linked group.
#
# Trigger conditions (from disassembly):
#
#   [A] Null session arg (RSI == 0): returns 0 without bypass at 0x2414099.
#
#   [B] Third arg (r12d) == 2 OR r12d == 14:
#       0x2413ea1: cmp $0x2, %r12d; setne %al
#       0x2413ea8: cmp $0xe, %r12d; setne %dl
#       0x2413eaf: and %dl, %al; jne bypass_path (0x2413f53)
#       → When r12d is NOT 2 AND NOT 14: falls through to inner call chain.
#       → When r12d IS 2: follows separate path at 0x2413ec1.
#       → When r12d IS 14: same join.
#       → Values 2 and 14 represent specific error/state conditions in the
#         QUIC session state machine (unidentified without symbol table).
#
#   [C] Inner call chain result:
#       0x2413ee1: call 0x2411820  → if 0: bypass path at 0x24140a0
#       0x2413ef8: call 0x2410420  → if 0: bypass path at 0x2414215
#       Both functions unknown (stripped); non-zero means "session still active."
#
# Bypass state write (confirmed from disassembly):
#   movl $0x2, 0x5b8(%rbx)   # sets session state field at +0x5b8 to BYPASS (2)
#   movl $0x2, 0x8c8(%rbx)   # sets session state field at +0x8c8 to BYPASS (2)
#   mov  0x5a0(%rbx), %rbx   # follow 'next' pointer in session linked list
#   → Propagates BYPASS to all sessions in the connection group via linked list.
#
# Debug logging gate:
#   testb $0x10, 0x4c7a652(%rip)   # bit 0x10 in global debug word @ 0x708e5b8
#   testb $0x40, 0x4c7a5c5(%rip)   # bit 0x40 in same word
#   → Debug log fires when either bit set, but bypass state write happens
#     unconditionally afterward.
#
# Session 0-RTT/tracker field check:
#   0x2413f68: cmpb $0x0, 0x1978(%r13)
#   → byte at offset 0x1978 in the tracker struct (r13) is checked only
#     for selecting between two log strings (cmovne at 0x2413f95).
#     NOT a bypass gate — the bypass write is independent of this field.
#
# Bypass revert:
#   No revert mechanism found. Once bypass state (0x2) is written to 0x5b8/0x8c8,
#   the only transitions observed are 0x5b8==2 checks that skip the write:
#     0x2413f18: cmpl $0x2, 0x8c8(%rbx); jne 0x2414006 → re-writes if not 2
#   Bypass appears sticky until session teardown.
#
QUIC_BYPASS_STATE_MACHINE = {
    'fn_va':               0x02413e27,
    'arg3_check_2':        0x02413ea1,  # cmp $0x2, %r12d
    'arg3_check_14':       0x02413ea8,  # cmp $0xe, %r12d
    'inner_call_1':        0x02413ee1,  # call 0x2411820 (unknown; 0=bypass)
    'inner_call_2':        0x02413ef8,  # call 0x2410420 (unknown; 0=bypass)
    'state_write_5b8':     0x02414006,  # movl $0x2, 0x5b8(%rbx) → BYPASS
    'state_write_8c8':     0x02414010,  # movl $0x2, 0x8c8(%rbx) → BYPASS
    'next_ptr_offset':     0x5a0,       # linked list next pointer in session obj
    'state_field_offset':  0x5b8,       # session state, value 2 = BYPASS
    'state_field2_offset': 0x8c8,       # second state field, value 2 = BYPASS
    'tracker_field_0x1978': 0x1978,     # byte in tracker struct; affects log only
    'debug_flag_va':       0x708e5b8,   # global debug word; bits 0x10/0x40 gate logging
    'linked_list_propagation': True,    # bypass propagates to all group sessions
    'sticky': True,                     # no revert observed; persists until teardown
    'bypass_string_va':    0x0437b569,  # "snp_quic_proxy_bypass"
    'switch_fn_string_va': 0x0472e6b0,  # "quic_trk_switch_to_bypass"
    'note': (
        'Bypass activates when inner validation calls (0x2411820, 0x2410420) return 0, '
        'or when the third argument is a specific error state (2 or 14). '
        'Propagation via 0x5a0 linked list means one errored session bypasses '
        'inspection for all sessions in the connection group.'
    ),
}


# ── F03: QUIC handshake tracker — TLS key material storage ────────────────────
#
# Strings at .rodata confirm the QUIC tracker stores both EC and RSA private keys:
#   "snp_quic_trk_set_ec_priv_key"  @ 0x0472e670
#   "snp_quic_trk_set_rsa_priv_key" @ 0x0472e690
#
# Context:
#   The QUIC tracker implements a TLS 1.3 interception layer — it intercepts
#   the QUIC-TLS handshake to derive traffic secrets and decrypt/re-encrypt
#   QUIC application data for inspection.
#
#   To sign the CertificateVerify message on behalf of the server during
#   handshake interception, the tracker needs the server's private key material.
#   These two functions store that key into the tracker object.
#
# Related functions (name strings in .rodata):
#   quic_trk_generate_server_cert_verify      — ASA generates CertVerify msg
#   quic_trk_generate_server_cert_verify_cb   — callback variant
#   quic_trk_generate_server_cert_verify_ec   — EC-specific path
#   quic_trk_generate_server_cert_verify_sync — synchronous variant
#   quic_trk_create_certificate_verify_data   — builds the signed TBS
#   quic_trk_sign_cert_verify_sw              — software signing path
#   quic_verify_generic_signature             — verify incoming cert sig
#   quic_verify_RSA_PSS_RSAE_signature        — RSA-PSS variant
#
#   quic_trk_derive_finished_hmac             — derives Finished HMAC key
#   quic_trk_finished_encrypt_msg             — encrypts Finished message
#   quic_trk_finished_verify                  — verifies incoming Finished MAC
#   quic_trk_gen_sec_params                   — derives HKDF secrets
#   quic_trk_gen_hs_sec_params                — handshake-layer secrets
#   quic_trk_gen_app_sec_params               — application-layer secrets
#   quic_trk_gen_and_send_resumption_master_secret — session resumption
#   quic_trk_secret_meta_init                 — secret metadata initialization
#   quic_trk_secrets_dump                     — debug secret dump
#
# quic_trk_finished_verify at 0x023ffd22:
#   Returns 1 on MAC mismatch (failure).
#   Caller pattern: test %eax, %eax; je success → error = bypass or teardown.
#   Debug gate: testb $0x10, 0x4c8e7c7(%rip) [= global 0x708e5b8]
#   Two exit paths — both return 1; no "ignore failure" path in this function.
#
# Security observations:
#   1. EC and RSA private key material stored in the tracker heap object.
#      If the tracker object is accessible from an overflow or UAF in the
#      QUIC parsing path, key material is recoverable.
#   2. quic_trk_secrets_dump string present — debug path that prints secrets.
#      Global debug bit gate unknown; if reachable, secrets logged to syslog/console.
#   3. quic_trk_gen_and_send_resumption_master_secret — session resumption secret
#      is generated and SENT. This implies the ASA can issue a NewSessionTicket,
#      meaning it holds the resumption key. Stolen ticket allows resumption
#      without re-authentication.
#
QUIC_TRACKER_KEY_MATERIAL = {
    'set_ec_priv_key_str':   0x0472e670,
    'set_rsa_priv_key_str':  0x0472e690,
    'cert_verify_fn_str':    None,  # quic_trk_generate_server_cert_verify in .rodata
    'secrets_dump_str':      None,  # quic_trk_secrets_dump in .rodata
    'resumption_secret_str': None,  # quic_trk_gen_and_send_resumption_master_secret
    'finished_verify_va':    0x023ffd22,
    'finished_verify_ret':   (1, 'FAILURE'),
    'threat_model': [
        'Key material in heap tracker object — recoverable via adjacent heap corruption',
        'quic_trk_secrets_dump — debug path; gated on global bit; secrets to log if reachable',
        'Resumption master secret generated and sent → full session resumption without re-auth',
        'CertificateVerify signing requires server private key in tracker → ASA impersonates server',
    ],
}


# ── F04: 0-RTT handling ───────────────────────────────────────────────────────
#
# Strings in .rodata (9.22.2.32):
#   "QUIC 0RTT Packet received"   @ 0x04966c91
#   "QUIC Proxy 0RTT packet drop" @ 0x047a2ee5
#   "QUIC_0_RTT"                  @ 0x047b0389
#
# "QUIC Proxy 0RTT packet drop" — the proxy layer DROPS 0-RTT packets.
# The string "QUIC 0RTT Packet received" is used in a static initialization
# context (found in a string-table loading sequence at 0x2b41f4a), not in
# a packet processing path.
#
# Interpretation:
#   ASA QUIC proxy does not support 0-RTT data forwarding. 0-RTT packets
#   are dropped at the proxy layer. This eliminates the 0-RTT replay window
#   at the proxy level. However:
#   - The "received" log string suggests 0-RTT packets are logged (not silently dropped).
#   - The tracker still processes 0-RTT handshake keys (quic_trk_gen_app_sec_params
#     may derive early data keys for inspection purposes even if forwarding is dropped).
#   - Client retransmits in 1-RTT after proxy drops; session proceeds with additional RTT.
#
QUIC_0RTT_HANDLING = {
    'proxy_drops_0rtt':     True,   # "QUIC Proxy 0RTT packet drop" confirms
    'string_received':      0x04966c91,  # in static init; not a per-packet handler
    'string_drop':          0x047a2ee5,
    'enum_0rtt':            0x047b0389,
    'replay_risk':          'LOW — proxy drops 0-RTT; no replay forwarding to backend',
    'caveat': (
        '0-RTT drop adds 1 RTT latency for QUIC clients using session resumption. '
        'If the ASA tracks early data keys internally (for inspection), key material '
        'for 0-RTT exists in the tracker even though packets are dropped.'
    ),
}


# ── F05: DoS surface — QUIC connection state table ────────────────────────────
#
# Strings in .rodata:
#   "Quic protocol connection maximum in-flight = %d"
#   "QUIC protocol connection maximum in-flight support is disabled"
#   "Quic protocol connection maximum in-flight was configured = %llu"
#   "Quic protocol connection maximum in-flight out of allowed range of <0 - 80>"
#   Debug command: "3. QUIC protocol connection maximum in-flight packets '3 <0 -- 80>', 0 is disable"
#   Retire timeout: "Quic protocol retire timeout argument out of allowed range of <2 - 60>"
#
# In-flight connection tracking:
#   Max in-flight packets configurable 0–80 per connection (0 = disabled).
#   Retire timeout configurable 2–60 seconds.
#   snp_quic_set_conn_embryonic — embryonic connection timer
#   snp_quic_proxy_on_embryonic_timer_expiry — timer callback
#
# DoS surface:
#   1. Embryonic QUIC connections (SYN-equivalent: UDP Initial packet).
#      Unlike TCP, QUIC Initial packets can use source-address spoofing.
#      If the embryonic timer is long (up to 60s), an attacker can exhaust
#      the in-flight connection table with 80 spoofed Initials per connection
#      entry before being evicted.
#   2. snp_quic_protect_against_dos_attack at 0x0472bbe0 suggests an explicit
#      DoS mitigation function exists. The string "snp_quic_dos_attack_avoided"
#      confirms a detection path. Nature of protection unknown without disassembly.
#   3. QUIC stateless reset (snp_quic_is_stateless_reset, snp_quic_proxy_stateless_reset_upstream):
#      Stateless reset tokens are per-CID. If the token can be derived or brute-forced,
#      an attacker can terminate arbitrary QUIC connections.
#
QUIC_DOS_SURFACE = {
    'max_inflight_range':   (0, 80),   # configured per connection
    'retire_timeout_range': (2, 60),   # seconds
    'embryonic_fn':         'snp_quic_set_conn_embryonic',
    'embryonic_timer_cb':   'snp_quic_proxy_on_embryonic_timer_expiry',
    'dos_protect_fn_str':   0x0472bbe0,  # "snp_quic_protect_against_dos_attack"
    'dos_avoided_str':      None,        # "snp_quic_dos_attack_avoided"
    'stateless_reset_token': 'snp_quic_trk_get_stateless_reset_token',
    'risks': [
        'Embryonic connection exhaustion via spoofed UDP Initials (no handshake required)',
        'Stateless reset token oracle if token derivation is predictable',
        'in-flight=0 (disabled) removes per-connection limit — global table exhaustion',
    ],
}


# ── F06: QUIC version negotiation attack surface ──────────────────────────────
#
# Strings:
#   "QUIC Version Supported is V1"      @ 0x04966ce0
#   "QUIC Version Negotiation on upstream"
#   "QUIC_PROXY_VERSION_UNSUPPORTED"    @ 0x0478ba40
#   "QUIC Version information will be loaded through default values"
#   "QUIC Version information will be read from available json file"
#   "5. QUIC Version Info Read from file."
#   "6. QUIC Version Info Load Default Values."
#   snp_quic_load_version_information
#   snp_quic_proxy_update_version_label_table
#   snp_quic_handle_unsupported_version_pkt
#   snp_quic_send_version_negotiation_pkt
#
# Version handling:
#   Supported: QUIC v1 (0x00000001) — confirmed by "QUIC Version Supported is V1".
#   Version info loadable from JSON file (debug command 5 in QUIC debug table).
#   An unsupported version triggers snp_quic_handle_unsupported_version_pkt.
#
# Attack surface:
#   1. Version downgrade via VN packet injection: attacker sends a spoofed
#      Version Negotiation packet to the client (before handshake completes)
#      listing only versions the ASA does not support. Client aborts or falls
#      back. ASA is transparent to this attack but its presence on-path means
#      it must handle the VN exchange correctly.
#   2. JSON version file: if the version configuration file is writable, an
#      attacker with filesystem access can add version IDs to expand the
#      inspection surface. Path unknown (no path string found in this search).
#   3. Unknown version in Initial packet: triggers snp_quic_handle_unsupported_version_pkt.
#      Parser still reads the full long header before version check — version
#      is stored at output+0x48 and checked later. Length guards protect against
#      truncated packets; no per-version size constraint exists.
#
QUIC_VERSION_SURFACE = {
    'supported_version':       0x00000001,  # QUIC v1 (RFC 9000)
    'version_string_va':       0x04966ce0,
    'unsupported_error_str':   0x0478ba40,
    'version_load_fn':         'snp_quic_load_version_information',
    'version_update_fn':       'snp_quic_proxy_update_version_label_table',
    'unsupported_handler':     'snp_quic_handle_unsupported_version_pkt',
    'vn_send_fn':              'snp_quic_send_version_negotiation_pkt',
    'json_config':             True,   # version list loadable from JSON file
    'risks': [
        'JSON version file path unknown — audit filesystem permissions if identified',
        'VN packet injection (off-path) not mitigated by ASA (transparent to attack)',
    ],
}


# ── QUIC attack surface summary ───────────────────────────────────────────────

FINDINGS = {
    'F01_LONG_HEADER_PARSER': {
        'fn': 'quic_decode_hd_long',
        'va': 0x01589990,
        'severity': 'INFO',
        'title': 'QUIC long header parser — correctly bounded, no overflow identified',
        'detail': (
            'All CID copies capped at 20 bytes in helper (0x158c000). '
            'VLI token/payload length bounded against remaining bytes. '
            'Stack canary on version read. No overflow path confirmed.'
        ),
        'fuzzing_targets': [
            'VLI encoding: first byte 0xff (8-byte VLI, length claims full packet)',
            'SCID_len = 20 with exactly 0 remaining bytes (off-by-one in bounds check)',
            'Multiple back-to-back long headers in one UDP datagram',
        ],
    },
    'F02_BYPASS_STATE_MACHINE': {
        'fn': 'func@0x02413e27',
        'va': 0x02413e27,
        'severity': 'MEDIUM',
        'title': 'QUIC bypass propagates to all group sessions on inner call failure',
        'detail': (
            'When either inner call (0x2411820 or 0x2410420) returns 0, ALL sessions '
            'in the QUIC connection group are set to bypass (state=2 at +0x5b8/+0x8c8). '
            'A crafted packet that causes the inner validation to return 0 bypasses '
            'QUIC inspection for the entire group. Bypass is sticky (no revert).'
        ),
        'trigger': 'inner calls return 0 (session validity check fails)',
        'impact': 'QUIC inspection bypassed → uninspected traffic forwarded',
    },
    'F03_KEY_MATERIAL_IN_TRACKER': {
        'fn': 'snp_quic_trk_* key functions',
        'va': 0x0472e670,  # set_ec_priv_key string
        'severity': 'HIGH',
        'title': 'QUIC tracker stores server EC/RSA private key in heap object',
        'detail': (
            'snp_quic_trk_set_ec_priv_key and snp_quic_trk_set_rsa_priv_key store '
            'private key material in the QUIC tracker heap object. '
            'quic_trk_gen_and_send_resumption_master_secret generates and emits '
            'NewSessionTickets, holding resumption keys. '
            'quic_trk_secrets_dump provides a debug path to log all secrets. '
            'Key material recoverable via heap corruption adjacent to tracker object.'
        ),
        'chained_with': 'F01_LONG_HEADER_PARSER (heap layout), F02_BYPASS_STATE_MACHINE',
    },
    'F04_0RTT_DROP': {
        'fn': 'QUIC proxy 0-RTT handling',
        'va': 0x047a2ee5,  # drop string
        'severity': 'INFO',
        'title': '0-RTT packets dropped at proxy — no replay forwarding',
        'detail': 'Proxy drops all 0-RTT data. Replay attack surface at proxy layer is closed.',
    },
    'F05_DOS_EMBRYONIC': {
        'fn': 'snp_quic_set_conn_embryonic',
        'va': None,
        'severity': 'MEDIUM',
        'title': 'QUIC embryonic connection table exhaustion via spoofed UDP Initial',
        'detail': (
            'QUIC Initial packets require no handshake completion before consuming '
            'connection table state. Retire timeout 2–60s. An attacker can exhaust '
            'the in-flight connection table (max 0–80 per connection) with spoofed '
            'source addresses, denying QUIC connectivity.'
        ),
    },
    'F06_JSON_VERSION_CONFIG': {
        'fn': 'snp_quic_load_version_information',
        'va': None,
        'severity': 'LOW',
        'title': 'QUIC version list loaded from JSON file — audit file permissions',
        'detail': (
            'Debug command 5 ("QUIC Version Info Read from file") triggers version '
            'list reload from JSON. If file is writable by non-root, an attacker '
            'can inject arbitrary version IDs to expand the QUIC parsing surface.'
        ),
    },
}
