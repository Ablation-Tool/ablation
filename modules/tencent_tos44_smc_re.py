"""
TencentOS 4.4 — SMC module pair RE: smc_tos44.ko + smc_kernel.ko.

SMC = Shared Memory Communications over RDMA (RFC 7609).
IBM-originated protocol that transparently replaces TCP with RDMA when
both endpoints support it — bypasses TCP stack, uses RDMA for data transfer.

Both modules target kernel 6.6.110-42.4.tl4.x86_64 (TOS 4.4, sig key D8:37:BC).
Note: smc.ko.xz (TOS 4.6) was empty in the scratchpad — TOS 4.4 modules only.

Two-module design reflects TOS's MLNX OFED coexistence strategy:
  smc_tos44.ko  (7903B)   — MLNX OFED stub, squats 'smc' module name
  smc_kernel.ko (641327B) — upstream IBM SMC stack (net/smc/)
"""

METADATA = {
    "kernel": "6.6.110-42.4.tl4.x86_64",
    "tos_version": "4.4",
    "sig_key": "D8:37:BC:3B:9C:28:FD:F6",
    "sig_hashalgo": "sha512",
    "signer": "Tkernel signing key",
    "modules": {
        "smc_tos44": {
            "size_bytes": 7903,
            "description": "smc dummy kernel module",
            "author": "Alaa Hleihel",
            "version": "4.1",
            "license": "Dual BSD/GPL",
            "srcfile": "smc_dummy.c",
            "depends": "mlx_compat",
            "purpose": "MLNX OFED stub — prevents smc_kernel.ko from loading when Mellanox drivers present",
        },
        "smc_kernel": {
            "size_bytes": 641327,
            "description": "smc socket address family",
            "author": "Ursula Braun <ubraun@linux.vnet.ibm.com>",
            "license": "GPL",
            "aliases": ["net-pf-43", "tcp-ulp-smc", "net-pf-16-proto-16-family-SMC_GEN_NETLINK"],
            "depends": "ib_core",
            "intree": True,
            "purpose": "Full IBM upstream SMC stack (SMC-R over RoCE + SMC-D over ISM)",
        },
    },
}

SMC_PROTOCOL_OVERVIEW = {
    "protocol": "SMC — Shared Memory Communications (RFC 7609)",
    "variants": {
        "SMC-R": {
            "transport": "RDMA over RoCE (RDMA over Converged Ethernet)",
            "mechanism": "RDMA Write for data, LLC (Link Layer Control) for signaling",
            "discovery": "Physical network identifier (pnetid) matching between peers",
        },
        "SMC-D": {
            "transport": "ISM (Internal Shared Memory) — IBM z/OS channel",
            "mechanism": "Direct Memory Access via ISM device",
            "note": "z/VM and z/OS only — requires IBM ISM hardware",
        },
    },
    "handshake": {
        "initial": "CLC (Connection Layer Control) messages over TCP",
        "proposal": "SMC_CLC_PROPOSAL — client sends capabilities",
        "accept": "SMC_CLC_ACCEPT — server confirms SMC-R or SMC-D",
        "confirm": "SMC_CLC_CONFIRM — both sides commit",
        "fallback": "If peer doesn't support SMC → stay on TCP (transparent fallback)",
    },
    "data_plane": {
        "CDC": "Connection Data Control — signals TX/RX state via RDMA",
        "LLC": "Link Layer Control — manages RDMA link groups (LGRs)",
        "sndbuf": "Sender's RDMA-registered buffer (SMC-R)",
        "rcvbuf": "Receiver's RDMA-registered buffer (SMC-R)",
    },
    "socket_family": "AF_SMC (43) — new socket family; tcp-ulp-smc allows transparent upgrade",
}

SMC_TOS44_STUB_ANALYSIS = {
    "purpose": "MLNX OFED SMC stub — module name collision prevention",
    "mechanism": (
        "The Linux module system uses the module name to resolve dependencies. "
        "When mlx_compat is present (MLNX OFED installed), smc_tos44.ko loads first "
        "as the 'smc' module. This satisfies any 'depends: smc' requirement and "
        "prevents the kernel from loading smc_kernel.ko. "
        "MLNX OFED then provides its own SMC implementation (better optimized for "
        "Mellanox ConnectX RDMA hardware) through a separate driver stack. "
        "The stub does nothing except satisfy the module dependency graph."
    ),
    "init_module_sequence": [
        "call __init_backport — mlx_compat module init hook (backport symbol resolution)",
        "xor %eax,%eax — return 0 (success)",
    ],
    "cleanup_module_sequence": [
        "jmp smc_cleanup — calls smc_cleanup() which does nothing in the stub",
    ],
    "smc_cleanup": "Empty function — no state to clean up in a stub",
    "author_context": (
        "Alaa Hleihel writes Mellanox/NVIDIA RDMA kernel drivers and mlx_compat. "
        "mlx_compat_dependency_symbol is the standard MLNX OFED mechanism for "
        "ensuring MLNX OFED modules load before upstream equivalents. "
        "This pattern is used across multiple kernel subsystems when MLNX OFED is installed."
    ),
}

SMC_KERNEL_ANALYSIS = {
    "source": "net/smc/ in Linux kernel tree (IBM upstream, merged 4.11)",
    "bpf_tracepoints": {
        "smc_switch_to_fallback": {
            "exported": True,
            "purpose": "Fired when SMC handshake fails and connection falls back to TCP",
            "data": "sk pointer, clcsk pointer, net namespace, fallback_rsn (reason code)",
            "format": "sk=%p clcsk=%p net=%llu fallback_rsn=%d",
        },
        "smc_tx_sendmsg": {
            "exported": True,
            "purpose": "Fired on each SMC sendmsg() call",
            "data": "smc pointer, net namespace, length, device name",
            "format": "smc=%p net=%llu len=%zu dev=%s",
        },
        "smc_rx_recvmsg": {
            "exported": True,
            "purpose": "Fired on each SMC recvmsg() call",
        },
        "smcr_link_down": {
            "exported": True,
            "purpose": "Fired when an SMC-R RDMA link goes down",
        },
    },
    "smc_header": {
        "file": "linux/smc.h (TOS 4.6 header — upstream, no TOS extensions)",
        "netlink_commands": [
            "SMC_NETLINK_GET_SYS_INFO", "SMC_NETLINK_GET_LGR_SMCR",
            "SMC_NETLINK_GET_LINK_SMCR", "SMC_NETLINK_GET_LGR_SMCD",
            "SMC_NETLINK_GET_DEV_SMCD", "SMC_NETLINK_GET_DEV_SMCR",
            "SMC_NETLINK_GET_STATS", "SMC_NETLINK_GET_FBACK_STATS",
            "SMC_NETLINK_DUMP_UEID", "SMC_NETLINK_ADD_UEID",
            "SMC_NETLINK_REMOVE_UEID", "SMC_NETLINK_FLUSH_UEID",
            "SMC_NETLINK_DUMP_SEID", "SMC_NETLINK_ENABLE_SEID",
            "SMC_NETLINK_DISABLE_SEID",
            "SMC_NETLINK_DUMP_HS_LIMITATION",
            "SMC_NETLINK_ENABLE_HS_LIMITATION",
            "SMC_NETLINK_DISABLE_HS_LIMITATION",
        ],
        "note": "No TOS-specific netlink commands — identical to upstream Linux 6.6",
    },
    "key_subsystems": {
        "CLC": "smc_clc.c — Connection Layer Control handshake over TCP before RDMA switch",
        "LLC": "smc_llc.c — Link Layer Control for link group management",
        "CDC": "smc_cdc.c — Connection Data Control (data plane signaling)",
        "pnet": "smc_pnet.c — Physical Network ID matching (maps Ethernet to RDMA device)",
        "ib": "smc_ib.c — InfiniBand/RoCE device management",
        "core": "smc_core.c — Link group (LGR) lifecycle",
    },
    "tos_modifications": "None visible — module is upstream SMC, compiled for TOS 4.4 kernel",
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "MLNX OFED stub (smc_tos44.ko) prevents upstream SMC from loading silently",
        "detail": (
            "smc_tos44.ko registers as the 'smc' module and immediately exits "
            "without providing any SMC socket family implementation. "
            "When MLNX OFED is installed, 'modprobe smc' loads the stub, not smc_kernel.ko. "
            "Applications using AF_SMC=43 sockets get EAFNOSUPPORT. "
            "SMC-R connections via 'tcp-ulp-smc' fail silently — TCP fallback occurs. "
            "A user expecting transparent TCP→SMC acceleration gets plain TCP "
            "because the stub says 'smc is loaded' but provides nothing. "
            "On TOS hosts where mlx_compat is present but MLNX OFED's SMC driver "
            "is not fully installed, all SMC traffic falls back to TCP permanently "
            "with no error logged beyond the fallback trace."
        ),
        "affected_scenario": "MLNX OFED partial install (mlx_compat present, OFED SMC absent)",
        "observable_symptom": "smc_switch_to_fallback trace fires on every connection",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "SMC-R RDMA buffers registered with RDMA device — memory exposure to RDMA peers",
        "detail": (
            "SMC-R registers application memory with the RDMA NIC (RKEY/LKEY via ib_reg_mr). "
            "The registered memory regions (RMRs) are accessible by the remote peer "
            "for RDMA Write operations during data transfer. "
            "If the LLC link management protocol has a bug and sends the wrong RMR key "
            "to a peer, the peer can read or write arbitrary process memory via RDMA. "
            "Unlike TCP, RDMA bypasses the kernel on the data path — there is no "
            "network stack interception point for intrusion detection. "
            "smc_clc_send_accept / smc_clc_send_confirm exchange RMR keys over TCP "
            "during the CLC handshake — these messages are unencrypted."
        ),
        "rmr_exchange": "CLC handshake sends RDMA memory registration keys in plaintext TCP",
        "threat": "MitM during CLC → inject fake RMR → RDMA peer reads/writes arbitrary process memory",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "smc_switch_to_fallback tracepoint: fallback_rsn logged — information disclosure",
        "detail": (
            "The smc_switch_to_fallback tracepoint logs: sk, clcsk, net namespace ID, fallback_rsn. "
            "fallback_rsn is a reason code for why the SMC handshake failed. "
            "Possible reason codes include: unsupported CLC version, no matching pnetid, "
            "no RDMA device found, peer declined. "
            "Any process with CAP_SYS_ADMIN (bpftrace) can attach to this tracepoint "
            "and observe every failed SMC handshake with the remote socket pointer "
            "and reason — effectively monitoring which connections fail to use SMC "
            "and why. On a multi-tenant host, this leaks information about "
            "other tenants' network RDMA capability and connection patterns."
        ),
        "exported_tracepoints": [
            "__SCT__tp_func_smc_switch_to_fallback",
            "__SCT__tp_func_smc_tx_sendmsg",
            "__SCT__tp_func_smc_rx_recvmsg",
            "__SCT__tp_func_smcr_link_down",
        ],
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "pnetid matching: smc_pnet_find_roce_by_pnetid — 16-char pnetid match controls RDMA path selection",
        "detail": (
            "SMC uses a Physical Network ID (pnetid, max 16 chars) to associate "
            "Ethernet interfaces with RDMA devices for RoCE. "
            "If two Ethernet interfaces are on the same physical network as an RDMA NIC, "
            "they share a pnetid. SMC uses this to select which RDMA device to use. "
            "pnetid can be configured via Netlink (SMC_PNETID_ADD) — any process with "
            "CAP_NET_ADMIN can modify the pnet table. "
            "A malicious process with CAP_NET_ADMIN can inject a fake pnetid entry "
            "pointing a target Ethernet interface to a controlled RDMA device, "
            "causing SMC-R connections to use a different (potentially monitored) "
            "RDMA path than intended."
        ),
        "pnetid_length": 16,
        "netlink_commands": ["SMC_PNETID_ADD", "SMC_PNETID_DEL", "SMC_PNETID_FLUSH"],
        "required_capability": "CAP_NET_ADMIN",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "Version mismatch: smc_tos44.ko is TOS 4.4, smc_kernel.ko is TOS 4.4 — no TOS 4.6 SMC in scratchpad",
        "detail": (
            "Both SMC modules have vermagic 6.6.110-42.4.tl4.x86_64 (TOS 4.4). "
            "The TOS 4.6 kernel is 6.6.119-51.3.tl4.x86_64. "
            "smc.ko.xz (the presumed TOS 4.6 SMC) was empty — likely a placeholder "
            "that was never populated in this firmware extract. "
            "Any TOS 4.6-specific SMC modifications (if any) cannot be determined "
            "from the scratchpad contents. "
            "If TOS 4.6 uses the same smc_kernel.ko without recompilation, "
            "the module would fail to load due to vermagic mismatch."
        ),
        "scratchpad_gap": "smc.ko.xz is empty; TOS 4.6 SMC module missing",
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "SMC-R CLC handshake over TCP: both peers negotiate, no authentication",
        "detail": (
            "SMC-R begins with a CLC (Connection Layer Control) handshake over the existing TCP connection. "
            "The handshake announces: hostname (SMC_MAX_HOSTNAME_LEN=32), EID (Enterprise ID, 32B), "
            "peer ID, RDMA registration key. "
            "There is no authentication in the CLC handshake — any TCP peer can attempt SMC negotiation. "
            "If both endpoints agree, they switch to RDMA. "
            "A peer that deliberately sends a malformed CLC ACCEPT triggers "
            "smc_switch_to_fallback and the connection stays on TCP. "
            "This is intentional (transparent fallback design) but means an attacker "
            "who can inject into the TCP stream can permanently prevent SMC-R from being used."
        ),
        "design_tradeoff": "Transparent TCP fallback = no authentication = denial-of-SMC is possible",
    },
]

if __name__ == '__main__':
    print("SMC module pair (TOS 4.4) RE analysis")
    print()
    for name, info in METADATA['modules'].items():
        print(f"  {name}: {info['description']} ({info['size_bytes']}B)")
    print()
    print("Protocol:")
    print(f"  SMC-R: {SMC_PROTOCOL_OVERVIEW['variants']['SMC-R']['transport']}")
    print(f"  SMC-D: {SMC_PROTOCOL_OVERVIEW['variants']['SMC-D']['transport']}")
    print()
    print("BPF tracepoints (smc_kernel.ko):")
    for tp in SMC_KERNEL_ANALYSIS['bpf_tracepoints']:
        print(f"  {tp}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
