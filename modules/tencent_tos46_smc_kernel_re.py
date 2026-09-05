"""
TencentOS — smc_kernel.ko RE (Shared Memory Communications over RDMA).

Two modules analyzed:
  smc_kernel.ko — full SMC-R/SMC-D implementation (TOS 4.4, 6.6.110-42.4.tl4)
  smc_tos44.ko  — stub/dummy module (TOS 4.4, 6.6.110-42.4.tl4)

Source: scratchpad/smc_kernel.ko, scratchpad/smc_tos44.ko

SMC (Shared Memory Communications, IBM RFC 7609/7610) is a TCP socket alternative
that transparently replaces TCP with RDMA when both endpoints support it.
Two modes:
  SMC-R: RDMA over InfiniBand/RoCE hardware
  SMC-D: Direct Memory Access via IBM ISM (Internal Shared Memory)

TOS ships smc_kernel.ko (full SMC implementation) alongside smc_tos44.ko (stub).
The stub is used when SMC-R/D hardware is unavailable; the full module provides
transparent TCP→SMC acceleration when the hardware is present.
"""

MODULE_METADATA = {
    "smc_kernel": {
        "filename": "smc_kernel.ko",
        "description": "smc socket address family",
        "author": "Ursula Braun <ubraun@linux.vnet.ibm.com>",
        "kernel": "6.6.110-42.4.tl4.x86_64",
        "license": "GPL",
        "origin": "IBM (mainline Linux, af_smc.c family)",
        "version_strings": ["llc_version", "smc_version", "smcr_version", "smcd_version"],
    },
    "smc_tos44": {
        "filename": "smc_tos44.ko",
        "description": "smc dummy kernel module",
        "author": "Alaa Hleihel",
        "version": "4.1",
        "kernel": "6.6.110-42.4.tl4.x86_64",
        "license": "GPL",
        "exported_symbols": ["cleanup_module", "init_module", "kill_block_whitelist_match"],
        "note": (
            "Stub placeholder — 4 symbols only. Provides the smc socket address family "
            "registration without actual SMC implementation. Used when SMC hardware is absent."
        ),
    },
}

SMC_FUNCTION_GROUPS = {
    "socket_operations": [
        "smc_accept",           # accept() on SMC listening socket
        "smc_bind",             # bind() — associates local addr with SMC socket
        "smc_accept_dequeue",   # dequeue completed accept from backlog
        "smc_clcsock_accept",   # CLC (connection layer control) socket accept
        "smc_clcsock_data_ready",  # data-ready callback for CLC socket
        "smc_clcsock_release",  # release CLC socket resources
    ],

    "connection_layer_control": {
        "description": (
            "CLC = Connection Layer Control. Negotiates SMC session parameters "
            "before switching from TCP to RDMA. Similar to TLS handshake."
        ),
        "functions": [
            "smc_clc_init",                     # init CLC subsystem
            "smc_clc_exit",                     # teardown CLC
            "smc_clc_get_hostname",             # get local hostname for CLC handshake
            "smc_clc_match_eid",                # match Enterprise ID for SMC-D
            "smc_clc_eid_table",                # Enterprise ID table management
            "smc_clc_ueid_add",                 # add user-space EID
            "smc_clc_ueid_count",               # count registered EIDs
            "smc_clc_ueid_remove",              # remove user-space EID
            "smc_clc_prfx_match",               # prefix match for routing
            "smc_clc_prfx_set",                 # set prefix routes
            "smc_clc_send_proposal",            # send CLC Proposal message
            "smc_clc_send_accept",              # send CLC Accept
            "smc_clc_send_confirm",             # send CLC Confirm
            "smc_clc_send_confirm_accept",      # combined Confirm+Accept
            "smc_clc_send_decline",             # send CLC Decline (fallback to TCP)
            "smc_clc_msg_hdr_valid",            # validate CLC message header
            "smc_clc_clnt_v2x_features_validate",  # v2 client feature negotiation
            "smc_clc_srv_v2x_features_validate",   # v2 server feature negotiation
            "smc_clc_v2x_features_confirm_check",  # v2 feature confirmation check
            "smc_clc_fill_fce_v2x",             # fill Feature Confirmation Extension
        ],
    },

    "data_channel_control": {
        "description": (
            "CDC = Connection Data Control. Manages RDMA data transfer after "
            "CLC handshake completes."
        ),
        "functions": [
            "smc_cdc_init",                 # init CDC for a connection
            "smc_cdc_get_free_slot",        # get free CDC slot for TX
            "smc_cdc_get_slot_and_msg_send",  # atomic: get slot + send CDC msg
            "smc_cdc_msg_send",             # send CDC control message via RDMA
            "smc_cdc_msg_recv",             # receive CDC message from peer
            "smc_cdc_msg_recv_action",      # process received CDC message
            "smc_cdc_rx_handler",           # RDMA RX completion handler
            "smc_cdc_rx_handlers",          # RX handler dispatch table
            "smc_cdc_tx_handler",           # RDMA TX completion handler
            "smc_cdc_wait_pend_tx_wr",      # wait for pending TX writes to complete
        ],
    },

    "buffer_management": [
        "smc_buf_create",   # allocate RDMA-registered shared memory buffer
        "smc_buf_free",     # free RDMA buffer and deregister from HCA
    ],

    "v2_ismlookup": [
        "smc_check_ism_v2_match",   # check ISM v2 device match for SMC-D
    ],
}

PROTOCOL_OVERVIEW = {
    "SMC_R": {
        "transport": "InfiniBand / RoCE (RDMA over Converged Ethernet)",
        "use_case": "Inter-server high-throughput communication",
        "handshake": "TCP connection established; CLC Proposal/Accept/Confirm sent; RDMA takeover",
        "data_path": "RDMA Write operations (zero-copy); CDC for flow control",
    },
    "SMC_D": {
        "transport": "IBM ISM (Internal Shared Memory) — shared memory between LPARs",
        "use_case": "Intra-host or intra-LPAR communication (VM-to-VM on same host)",
        "eid": "Enterprise ID table (smc_clc_eid_table) identifies ISM-capable pairs",
        "data_path": "Direct memory copy via ISM adapter; CDC for flow control",
    },
    "tcp_fallback": (
        "CLC Decline message triggers fallback to standard TCP. "
        "Application remains unaware of the transport switch — socket API is unchanged."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "MEDIUM",
        "title": "smc_buf_create allocates RDMA-registered memory: memory pinning DoS potential",
        "detail": (
            "smc_buf_create() registers user-facing shared memory with the RDMA HCA (ibv_reg_mr). "
            "Registered memory is pinned — it cannot be swapped out. "
            "A process that opens many SMC sockets and triggers buffer allocation can pin "
            "large amounts of physical memory, exhausting the system's pinned-memory budget "
            "and potentially causing OOM or degrading other workloads on the same host. "
            "The RDMA subsystem has per-process limits but enforcement depends on driver config."
        ),
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "title": "CLC negotiation: no authentication — transparent SMC upgrade trusts peer identity",
        "detail": (
            "CLC Proposal/Accept/Confirm exchange is unauthenticated. SMC assumes that "
            "the peer initiating the CLC handshake is the legitimate TCP peer. "
            "An on-path attacker who can intercept the TCP connection initiation can "
            "inject a CLC Proposal and upgrade the connection to SMC, potentially "
            "impersonating either endpoint in the RDMA session. "
            "The TCP connection itself may be TLS-protected (application layer), but "
            "the SMC upgrade happens below TLS — at the socket level."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "smc_tos44.ko: dummy stub with 4 symbols — used when SMC hardware absent",
        "detail": (
            "smc_tos44.ko (version 4.1, author Alaa Hleihel) is a stub that registers "
            "the smc socket AF without actual RDMA. 4 exported symbols: init/cleanup + "
            "kill_block_whitelist_match. "
            "When loaded instead of smc_kernel.ko, SMC socket creates fail gracefully "
            "with ENODEV or fall back to TCP. "
            "The stub prevents the AF_SMC socket type from being unregistered on "
            "kernels where SMC hardware isn't present."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "SMC v2 Enterprise ID (EID) table: SMC-D peer authentication via EID matching",
        "detail": (
            "smc_clc_eid_table and smc_clc_match_eid implement EID-based peer matching. "
            "For SMC-D connections, both endpoints must have matching EIDs. "
            "User-space can add/remove EIDs via smc_clc_ueid_add/remove. "
            "EIDs are used for ISM device selection — not cryptographic authentication."
        ),
    },
]

if __name__ == '__main__':
    print("SMC kernel module RE (Shared Memory Communications)")
    for mod, meta in MODULE_METADATA.items():
        print(f"  {mod}: {meta['description']} — {meta['author']}")
    print()
    print("Protocol modes:")
    for mode, info in PROTOCOL_OVERVIEW.items():
        if isinstance(info, dict):
            print(f"  {mode}: {info.get('transport', info.get('use_case', ''))[:60]}")
    print()
    print(f"Function groups: {len(SMC_FUNCTION_GROUPS)}")
    for group, data in SMC_FUNCTION_GROUPS.items():
        if isinstance(data, list):
            print(f"  {group}: {len(data)} functions")
        elif isinstance(data, dict) and "functions" in data:
            print(f"  {group}: {len(data['functions'])} functions")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
