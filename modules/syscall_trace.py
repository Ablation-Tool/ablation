#!/usr/bin/env python3
"""
Syscall Tracing Module
Synthesized from: Hacking: The Art of Exploitation, Linux System Programming

Trace syscalls for running processes using strace/ptrace.
"""

import subprocess
import re
import platform as _platform
from pathlib import Path

_IS_MACOS = _platform.system() == 'Darwin'
_IS_LINUX = _platform.system() == 'Linux'

class SyscallTracer:
    """Trace and analyze system calls"""
    
    def __init__(self, pid=None):
        self.pid = pid
        self.syscalls = []
        
    def trace_process(self, duration=5):
        """
        Trace syscalls for a running process
        
        Args:
            duration: seconds to trace (default 5)
        
        Returns:
            dict with syscall statistics
        """
        if not self.pid:
            raise ValueError("PID required for tracing")

        if _IS_MACOS:
            return self._trace_macos(duration)

        cmd = [
            'strace', '-p', str(self.pid),
            '-c', '-f', '-e', 'trace=all', '-T',
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration)
            return self._parse_strace_summary(result.stderr)
        except subprocess.TimeoutExpired as e:
            return self._parse_strace_summary(e.stderr.decode() if e.stderr else '')
        except PermissionError:
            return {'error': 'Permission denied - need CAP_SYS_PTRACE or root'}
        except FileNotFoundError:
            return {'error': 'strace not installed'}
        except Exception as e:
            return {'error': str(e)}

    def _trace_macos(self, duration):
        """macOS syscall tracing via dtruss (requires root + SIP disabled)"""
        try:
            result = subprocess.run(
                ['dtruss', '-p', str(self.pid)],
                capture_output=True, text=True, timeout=duration
            )
            lines = (result.stdout + result.stderr).strip().split('\n')
            counts = {}
            for line in lines:
                parts = line.split('(')
                if parts:
                    name = parts[0].strip()
                    if name:
                        counts[name] = counts.get(name, 0) + 1
            syscalls = sorted(
                [{'name': k, 'calls': v, 'errors': 0, 'time_percent': 0.0, 'total_time': 0.0}
                 for k, v in counts.items()],
                key=lambda x: x['calls'], reverse=True
            )
            return {'total_calls': sum(counts.values()), 'total_errors': 0, 'syscalls': syscalls}
        except subprocess.TimeoutExpired as e:
            lines = (e.stderr.decode() if e.stderr else '').strip().split('\n')
            counts = {}
            for line in lines:
                parts = line.split('(')
                if parts and parts[0].strip():
                    n = parts[0].strip()
                    counts[n] = counts.get(n, 0) + 1
            syscalls = sorted(
                [{'name': k, 'calls': v, 'errors': 0, 'time_percent': 0.0, 'total_time': 0.0}
                 for k, v in counts.items()],
                key=lambda x: x['calls'], reverse=True
            )
            return {'total_calls': sum(counts.values()), 'total_errors': 0, 'syscalls': syscalls}
        except PermissionError:
            return {'error': 'syscall tracing requires root + SIP disabled on macOS (dtruss)'}
        except FileNotFoundError:
            return {'error': 'syscall tracing requires dtrace/dtruss on macOS (root + SIP disabled)'}
        except Exception as e:
            return {'error': str(e)}
    
    def trace_detailed(self, duration=5, syscall_filter=None):
        """
        Detailed syscall trace with arguments
        
        Args:
            duration: seconds to trace
            syscall_filter: specific syscalls to trace (e.g., 'open,read,write')
        
        Returns:
            list of syscall entries
        """
        if not self.pid:
            raise ValueError("PID required for tracing")

        if _IS_MACOS:
            return [{'error': 'detailed trace requires dtruss on macOS (root + SIP disabled)'}]

        cmd = ['strace', '-p', str(self.pid), '-f', '-s', '256', '-v', '-tt']
        if syscall_filter:
            cmd.extend(['-e', f'trace={syscall_filter}'])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration)
            return self._parse_strace_detailed(result.stderr)
        except subprocess.TimeoutExpired as e:
            stderr = e.stderr.decode() if e.stderr else ''
            return self._parse_strace_detailed(stderr)
        except Exception as e:
            return [{'error': str(e)}]
    
    def _parse_strace_summary(self, output):
        """Parse strace -c summary output"""
        stats = {
            'total_calls': 0,
            'total_errors': 0,
            'syscalls': []
        }
        
        # Look for summary table
        lines = output.split('\n')
        in_summary = False
        
        for line in lines:
            if '% time' in line and 'seconds' in line:
                in_summary = True
                continue
            
            if in_summary and line.strip() and not line.startswith('-'):
                # Parse line: % time  seconds  usecs/call  calls  errors syscall
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        percent = float(parts[0])
                        seconds = float(parts[1])
                        calls = int(parts[3])
                        errors = int(parts[4]) if parts[4] != '-' else 0
                        syscall = parts[5]
                        
                        stats['syscalls'].append({
                            'name': syscall,
                            'calls': calls,
                            'errors': errors,
                            'time_percent': percent,
                            'total_time': seconds
                        })
                        
                        stats['total_calls'] += calls
                        stats['total_errors'] += errors
                    except:
                        pass
        
        # Sort by calls
        stats['syscalls'] = sorted(stats['syscalls'], key=lambda x: x['calls'], reverse=True)
        
        return stats
    
    def _parse_strace_detailed(self, output):
        """Parse detailed strace output"""
        syscalls = []
        
        # Pattern: timestamp pid syscall(args) = retval
        pattern = r'(\d+:\d+:\d+\.\d+)\s+(\w+)\((.*?)\)\s+=\s+([-\d]+|0x[0-9a-f]+|\?)'
        
        for match in re.finditer(pattern, output):
            timestamp = match.group(1)
            syscall = match.group(2)
            args = match.group(3)
            retval = match.group(4)
            
            entry = {
                'timestamp': timestamp,
                'syscall': syscall,
                'args': args,
                'return': retval,
                'error': retval.startswith('-') if retval != '?' else False
            }
            
            syscalls.append(entry)
        
        return syscalls
    
    def analyze_file_access(self, duration=5):
        """Trace file access syscalls"""
        return self.trace_detailed(duration, syscall_filter='open,openat,read,write,close,stat')
    
    def analyze_network(self, duration=5):
        """Trace network syscalls"""
        return self.trace_detailed(duration, syscall_filter='socket,connect,bind,listen,accept,send,recv')
    
    def analyze_process_ops(self, duration=5):
        """Trace process operations"""
        return self.trace_detailed(duration, syscall_filter='fork,clone,execve,exit,kill,wait4')
    
    def report(self, stats):
        """Generate human-readable report"""
        if 'error' in stats:
            return f"Error: {stats['error']}"
        
        lines = []
        lines.append(f"Syscall Trace Summary")
        lines.append("-" * 60)
        lines.append(f"Total calls: {stats['total_calls']}")
        lines.append(f"Total errors: {stats['total_errors']}")
        lines.append(f"\nTop syscalls by call count:")
        lines.append(f"{'Syscall':<20} {'Calls':<10} {'Errors':<10} {'Time %':<10}")
        lines.append("-" * 60)
        
        for sc in stats['syscalls'][:20]:
            lines.append(f"{sc['name']:<20} {sc['calls']:<10} {sc['errors']:<10} {sc['time_percent']:<10.2f}")
        
        return "\n".join(lines)

def detect_raw_socket_creation(pid=None) -> list:
    """
    Detect raw socket creation and promiscuous mode.
    Synthesized from: Hacking: The Art of Exploitation - Network Sniffing, Sockets chapters.

    Checks:
    - /proc/{pid}/net/raw or /proc/net/raw for active raw sockets (CAP_NET_RAW)
    - /proc/{pid}/net/packet or /proc/net/packet for packet sockets (link-layer access)
    - /sys/class/net/*/flags for promiscuous mode flag (0x100)
    - /proc/{pid}/status CapEff for CAP_NET_RAW (bit 13)

    Returns list of {severity, title, detail, host, port}.
    """
    import os
    import struct
    findings = []

    def _read_proc_net(path):
        try:
            with open(path, 'r') as f:
                lines = f.readlines()
            return [l.strip() for l in lines[1:] if l.strip()]
        except Exception:
            return []

    # raw socket table
    if pid is not None:
        raw_path = f'/proc/{pid}/net/raw'
        raw6_path = f'/proc/{pid}/net/raw6'
    else:
        raw_path = '/proc/net/raw'
        raw6_path = '/proc/net/raw6'

    raw_entries = _read_proc_net(raw_path) + _read_proc_net(raw6_path)
    if raw_entries:
        findings.append({
            'severity': 'HIGH',
            'title': 'RAW_SOCKET_ACTIVE',
            'detail': f'CAP_NET_RAW capability in use — {len(raw_entries)} raw socket(s) open ({raw_path})',
            'host': 'localhost',
            'port': 0,
        })

    # packet socket table
    if pid is not None:
        pkt_path = f'/proc/{pid}/net/packet'
    else:
        pkt_path = '/proc/net/packet'

    pkt_entries = _read_proc_net(pkt_path)
    if pkt_entries:
        findings.append({
            'severity': 'HIGH',
            'title': 'PACKET_SOCKET_ACTIVE',
            'detail': f'Direct link-layer access — {len(pkt_entries)} SOCK_PACKET/AF_PACKET socket(s) open ({pkt_path})',
            'host': 'localhost',
            'port': 0,
        })

    # promiscuous mode via /sys/class/net/*/flags
    net_class = Path('/sys/class/net')
    if net_class.exists():
        for iface_path in net_class.iterdir():
            flags_file = iface_path / 'flags'
            try:
                flags_val = int(flags_file.read_text().strip(), 16)
                if flags_val & 0x100:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'INTERFACE_IN_PROMISCUOUS_MODE',
                        'detail': f'Network sniffing active on interface {iface_path.name} (flags=0x{flags_val:x})',
                        'host': 'localhost',
                        'port': 0,
                    })
            except Exception:
                continue

    # CAP_NET_RAW in effective capabilities (bit 13)
    pids_to_check = [pid] if pid is not None else []
    if not pids_to_check:
        proc = Path('/proc')
        pids_to_check = [int(p.name) for p in proc.iterdir() if p.name.isdigit()]

    cap_net_raw_pids = []
    for p in pids_to_check:
        status_path = f'/proc/{p}/status'
        try:
            with open(status_path, 'r') as f:
                for line in f:
                    if line.startswith('CapEff:'):
                        cap_eff = int(line.split(':')[1].strip(), 16)
                        if cap_eff & (1 << 13):
                            cap_net_raw_pids.append(p)
                        break
        except Exception:
            continue

    if cap_net_raw_pids:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'PROCESS_HAS_CAP_NET_RAW',
            'detail': f'CAP_NET_RAW in effective capabilities for PID(s): {cap_net_raw_pids[:10]}',
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_ptrace_abuse() -> list:
    """
    Detect ptrace-based attack surfaces.
    Synthesized from: Hacking: The Art of Exploitation - Syscall tracing and ptrace abuse.

    Checks:
    - TracerPid in /proc/{pid}/status for all PIDs (non-zero = process being traced)
    - /proc/sys/kernel/yama/ptrace_scope value 0 (unrestricted ptrace)
    - Seccomp status 0 across all PIDs (no syscall filtering)

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    proc = Path('/proc')
    all_pids = [int(p.name) for p in proc.iterdir() if p.name.isdigit()]

    traced_pids = []
    seccomp_disabled_count = 0
    seccomp_total = 0

    for p in all_pids:
        status_path = f'/proc/{p}/status'
        try:
            with open(status_path, 'r') as f:
                tracer_pid = None
                seccomp_val = None
                for line in f:
                    if line.startswith('TracerPid:'):
                        tracer_pid = int(line.split(':')[1].strip())
                    elif line.startswith('Seccomp:'):
                        seccomp_val = int(line.split(':')[1].strip())
                if tracer_pid is not None and tracer_pid != 0:
                    traced_pids.append((p, tracer_pid))
                if seccomp_val is not None:
                    seccomp_total += 1
                    if seccomp_val == 0:
                        seccomp_disabled_count += 1
        except Exception:
            continue

    if traced_pids:
        detail_pairs = ', '.join(f'PID {pid} traced by {tpid}' for pid, tpid in traced_pids[:10])
        findings.append({
            'severity': 'HIGH',
            'title': 'PROCESS_BEING_TRACED',
            'detail': f'Potential code injection via ptrace — {detail_pairs}',
            'host': 'localhost',
            'port': 0,
        })

    # ptrace_scope
    ptrace_scope_path = '/proc/sys/kernel/yama/ptrace_scope'
    try:
        scope_val = int(Path(ptrace_scope_path).read_text().strip())
        if scope_val == 0:
            findings.append({
                'severity': 'HIGH',
                'title': 'PTRACE_SCOPE_0',
                'detail': 'Any process can attach to any other — /proc/sys/kernel/yama/ptrace_scope=0',
                'host': 'localhost',
                'port': 0,
            })
    except Exception:
        pass

    # seccomp disabled aggregate
    if seccomp_total > 0 and seccomp_disabled_count > 0:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SECCOMP_DISABLED',
            'detail': f'No syscall filtering on {seccomp_disabled_count}/{seccomp_total} inspectable processes',
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_socket_abuse_patterns() -> list:
    """
    Detect suspicious socket patterns from /proc/net tables.
    Synthesized from: Hacking: The Art of Exploitation - Sockets chapter (SOCK_RAW, bind, listen patterns).

    Checks:
    - /proc/net/tcp + /proc/net/tcp6: LISTEN on unprivileged port (>1024) from non-root UID
    - /proc/net/udp: connected UDP (foreign address non-zero) from non-root UID
    - /proc/net/unix: SOCK_STREAM world-accessible unix sockets

    Returns list of {severity, title, detail, host, port}.
    """
    import socket as _socket
    findings = []

    def _parse_net_table(path):
        rows = []
        try:
            with open(path, 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if parts:
                        rows.append(parts)
        except Exception:
            pass
        return rows

    def _hex_to_ip(hex_addr):
        try:
            addr, port = hex_addr.split(':')
            ip = _socket.inet_ntoa(bytes(reversed(bytes.fromhex(addr))))
            port_num = int(port, 16)
            return ip, port_num
        except Exception:
            return None, 0

    # TCP LISTEN from non-root on unprivileged port
    unprivileged_listens = []
    for tcp_file in ['/proc/net/tcp', '/proc/net/tcp6']:
        for row in _parse_net_table(tcp_file):
            try:
                # columns: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid ...
                local_hex = row[1]
                state = row[3]
                uid = int(row[7])
                if state == '0A' and uid != 0:  # 0A = TCP_LISTEN
                    _, port_num = _hex_to_ip(local_hex)
                    if port_num is not None and port_num > 1024:
                        unprivileged_listens.append((uid, port_num, tcp_file))
            except (IndexError, ValueError):
                continue

    if unprivileged_listens:
        sample = unprivileged_listens[:5]
        detail = '; '.join(f'UID={uid} port={p}' for uid, p, _ in sample)
        findings.append({
            'severity': 'MEDIUM',
            'title': 'UNPRIVILEGED_BIND_HIGH_PORT',
            'detail': f'Non-root process listening on unprivileged port — {detail}',
            'host': 'localhost',
            'port': unprivileged_listens[0][1],
        })

    # Connected UDP (foreign addr non-zero) from non-root
    connected_udp = []
    for udp_file in ['/proc/net/udp', '/proc/net/udp6']:
        for row in _parse_net_table(udp_file):
            try:
                foreign_hex = row[2]
                uid = int(row[7])
                if uid != 0:
                    _, fport = _hex_to_ip(foreign_hex)
                    if fport is not None and fport != 0:
                        connected_udp.append((uid, fport))
            except (IndexError, ValueError):
                continue

    if connected_udp:
        sample = connected_udp[:5]
        detail = '; '.join(f'UID={uid} foreign_port={p}' for uid, p in sample)
        findings.append({
            'severity': 'MEDIUM',
            'title': 'CONNECTED_UDP_SOCKET',
            'detail': f'Non-root connected UDP socket(s) — {detail}',
            'host': 'localhost',
            'port': 0,
        })

    # World-accessible UNIX SOCK_STREAM sockets
    world_unix = []
    for row in _parse_net_table('/proc/net/unix'):
        try:
            # columns: Num RefCount Protocol Flags Type St Inode Path
            if len(row) < 8:
                continue
            sock_type = int(row[4], 16)
            path = row[7] if len(row) > 7 else ''
            SOCK_STREAM = 1
            if sock_type == SOCK_STREAM and path and not path.startswith('@'):
                try:
                    st = os.stat(path)
                    if st.st_mode & 0o002:
                        world_unix.append(path)
                except Exception:
                    pass
        except (IndexError, ValueError):
            continue

    if world_unix:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'WORLD_ACCESSIBLE_UNIX_SOCKET',
            'detail': f'World-writable UNIX stream socket(s): {world_unix[:5]}',
            'host': 'localhost',
            'port': 0,
        })

    return findings


def check_network_sniffing_indicators() -> list:
    """
    Detect active network sniffing indicators.
    Synthesized from: Hacking: The Art of Exploitation - Network Sniffing chapter (promiscuous mode,
    packet capture tools, passive traffic interception).

    Checks:
    - `ip link show` output for PROMISC flag
    - /proc/net/dev RX vs TX packet ratio > 100 (passive sniffing signature)
    - /proc/*/cmdline for known sniffer process names

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # PROMISC via ip link show
    try:
        result = subprocess.run(
            ['/sbin/ip', 'link', 'show'],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
        promisc_ifaces = re.findall(r'(\S+):\s+<[^>]*PROMISC[^>]*>', output)
        if promisc_ifaces:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'PROMISC_MODE_CONFIRMED',
                'detail': f'Active sniffing — promiscuous mode on interface(s): {promisc_ifaces}',
                'host': 'localhost',
                'port': 0,
            })
    except Exception:
        pass

    # RX/TX ratio from /proc/net/dev
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()
        for line in lines[2:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            iface = parts[0].rstrip(':')
            if iface in ('lo',):
                continue
            try:
                rx_packets = int(parts[2])
                tx_packets = int(parts[10])
                if tx_packets > 0 and rx_packets / tx_packets > 100:
                    findings.append({
                        'severity': 'MEDIUM',
                        'title': 'HIGH_RX_TX_RATIO',
                        'detail': f'Possible passive sniffing on {iface} — RX {rx_packets} / TX {tx_packets} = ratio {rx_packets/tx_packets:.1f}',
                        'host': 'localhost',
                        'port': 0,
                    })
            except (ValueError, ZeroDivisionError):
                continue
    except Exception:
        pass

    # Known sniffer processes
    sniffer_names = {'tcpdump', 'wireshark', 'tshark', 'dumpcap', 'scapy'}
    found_sniffers = []
    proc = Path('/proc')
    for pid_dir in proc.iterdir():
        if not pid_dir.name.isdigit():
            continue
        cmdline_path = pid_dir / 'cmdline'
        try:
            cmdline = cmdline_path.read_bytes().replace(b'\x00', b' ').decode(errors='replace').strip()
            for sniffer in sniffer_names:
                if sniffer in cmdline:
                    found_sniffers.append((pid_dir.name, sniffer, cmdline[:120]))
                    break
        except Exception:
            continue

    if found_sniffers:
        detail = '; '.join(f'PID {p} ({s})' for p, s, _ in found_sniffers[:5])
        findings.append({
            'severity': 'HIGH',
            'title': 'KNOWN_SNIFFER_RUNNING',
            'detail': f'Known packet capture tool(s) active — {detail}',
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_dylib_hijacking_surface(binary_path=None, binary_data=None) -> list:
    """
    Detect dylib hijacking attack surface in a Mach-O binary.

    Synthesized from: The Art of Mac Malware (Wardle) — dylib hijacking,
    DYLD_INSERT_LIBRARIES injection, @rpath abuse, bundled framework injection.

    Args:
        binary_path: path to Mach-O binary (str or Path-like), or
        binary_data: raw bytes of the binary (takes priority over binary_path)
    Returns:
        list of {severity, title, detail, host, port}
    """
    import os
    import struct

    findings = []

    # Load binary data
    if binary_data is None:
        if binary_path is None:
            return findings
        try:
            with open(binary_path, 'rb') as _f:
                binary_data = _f.read()
        except Exception:
            return findings

    if len(binary_data) < 28:
        return findings

    # Mach-O load command constants
    LC_LOAD_DYLIB  = 0x0000000C
    LC_RPATH_NOFLG = 0x0000001C  # LC_RPATH with REQ flag stripped

    # Detect Mach-O magic (little-endian 32/64)
    magic = struct.unpack_from('<I', binary_data, 0)[0]
    MACHO_32 = 0xCEFAEDFE
    MACHO_64 = 0xCFFAEDFE
    is_macho = magic in (MACHO_32, MACHO_64, 0xFEEDFACE, 0xFEEDFACF)

    if is_macho:
        is64 = magic in (MACHO_64, 0xFEEDFACF)
        hdr_size = 32 if is64 else 28
        try:
            ncmds = struct.unpack_from('<I', binary_data, 16)[0]
        except Exception:
            ncmds = 0

        rpath_dirs = []
        tmp_dylibs = []
        framework_paths = []

        offset = hdr_size
        for _ in range(min(ncmds, 512)):
            if offset + 8 > len(binary_data):
                break
            try:
                cmd, cmdsize = struct.unpack_from('<II', binary_data, offset)
            except Exception:
                break
            if cmdsize < 8:
                break

            raw_cmd = cmd & 0x7FFFFFFF  # strip REQ bit

            if raw_cmd == LC_RPATH_NOFLG and offset + 12 <= len(binary_data):
                str_off = struct.unpack_from('<I', binary_data, offset + 8)[0]
                str_start = offset + str_off
                str_end = offset + cmdsize
                if 12 <= str_off < cmdsize and str_end <= len(binary_data):
                    rpath = binary_data[str_start:str_end].split(b'\x00', 1)[0].decode(errors='replace').strip()
                    rpath_dirs.append(rpath)

            elif raw_cmd == LC_LOAD_DYLIB and offset + 16 <= len(binary_data):
                str_off = struct.unpack_from('<I', binary_data, offset + 8)[0]
                str_start = offset + str_off
                str_end = offset + cmdsize
                if 16 <= str_off < cmdsize and str_end <= len(binary_data):
                    dylib_path = binary_data[str_start:str_end].split(b'\x00', 1)[0].decode(errors='replace').strip()
                    if dylib_path.startswith(('/tmp', '/var/tmp')):
                        tmp_dylibs.append(dylib_path)
                    if '/../Frameworks' in dylib_path and dylib_path.startswith(('@executable_path', '@loader_path')):
                        framework_paths.append(dylib_path)

            offset += cmdsize

        # Check rpath directories for writability
        for rpath in rpath_dirs:
            resolved = rpath
            if binary_path:
                bin_dir = os.path.dirname(os.path.abspath(str(binary_path)))
                resolved = rpath.replace('@executable_path', bin_dir).replace('@loader_path', bin_dir)
            if resolved.startswith('@'):
                continue  # unresolvable token
            try:
                if os.path.isdir(resolved) and os.access(resolved, os.W_OK):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'DYLIB_RPATH_HIJACK',
                        'detail': f'@rpath directory is writable — attacker can plant library at {resolved!r}',
                        'host': 'localhost',
                        'port': 0,
                    })
            except Exception:
                pass

        for dp in tmp_dylibs[:5]:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'DYLIB_LOADS_FROM_TMP',
                'detail': f'LC_LOAD_DYLIB references world-writable temp path: {dp!r}',
                'host': 'localhost',
                'port': 0,
            })

        if framework_paths:
            quarantine_present = False
            if binary_path:
                try:
                    quarantine_present = bool(os.getxattr(str(binary_path), 'com.apple.quarantine'))
                except (AttributeError, OSError):
                    pass  # Linux or no xattr
            if not quarantine_present:
                for fp in framework_paths[:5]:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'BUNDLED_FRAMEWORK_INJECTION_SURFACE',
                        'detail': (
                            f'Binary loads bundled framework via relative path ({fp!r}) without '
                            'Gatekeeper quarantine attribute — DYLD_INSERT_LIBRARIES injection surface'
                        ),
                        'host': 'localhost',
                        'port': 0,
                    })

    # String scan for DYLD_INSERT_LIBRARIES reference regardless of Mach-O validity
    if b'DYLD_INSERT_LIBRARIES' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title': 'DYLD_INSERT_LIBRARIES_REFERENCE',
            'detail': 'Binary references DYLD_INSERT_LIBRARIES — dylib injection or sandbox escape vector',
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_macos_task_port_abuse(binary_data: bytes) -> list:
    """
    Detect Mach task port and inter-process abuse primitives in a binary.

    Synthesized from: The Art of Mac Malware (Wardle) — task_for_pid cross-process
    memory access, Mach VM read/write primitives, bootstrap port service hijack,
    IOKit kernel connections, process info enumeration.

    Args:
        binary_data: raw bytes of the binary to scan
    Returns:
        list of {severity, title, detail, host, port}
    """
    findings = []

    if not binary_data:
        return findings

    # task_for_pid — grants Mach task port for arbitrary process
    if b'task_for_pid' in binary_data:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'TASK_FOR_PID_USAGE',
            'detail': (
                'Binary references task_for_pid — cross-process Mach task port acquisition; '
                'enables arbitrary memory read/write and thread injection into target process'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # mach_vm_read / mach_vm_write — direct Mach VM manipulation
    vm_refs = [s for s in (b'mach_vm_read', b'mach_vm_write') if s in binary_data]
    if vm_refs:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'MACH_VM_READ_WRITE',
            'detail': (
                'Binary references {} — arbitrary process memory manipulation via Mach VM API; '
                'facilitates code injection and credential theft'
            ).format(', '.join(r.decode() for r in vm_refs)),
            'host': 'localhost',
            'port': 0,
        })

    # bootstrap_look_up / bootstrap_register — Mach bootstrap port service hijack
    bs_refs = [s for s in (b'bootstrap_look_up', b'bootstrap_register') if s in binary_data]
    if bs_refs:
        findings.append({
            'severity': 'HIGH',
            'title': 'BOOTSTRAP_PORT_MANIPULATION',
            'detail': (
                'Binary references {} — Mach bootstrap service lookup/registration; '
                'enables XPC service squatting and privilege escalation via bootstrap port hijack'
            ).format(', '.join(r.decode() for r in bs_refs)),
            'host': 'localhost',
            'port': 0,
        })

    # IOConnectCallMethod + IOServiceOpen — IOKit kernel extension interaction
    if b'IOConnectCallMethod' in binary_data and b'IOServiceOpen' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title': 'IOKIT_KERNEL_CONNECTION',
            'detail': (
                'Binary uses IOConnectCallMethod + IOServiceOpen — direct IOKit kernel extension '
                'interaction; surface for kernel memory corruption and privilege escalation'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # proc_pidinfo / proc_listpids — process surveillance / enumeration
    proc_refs = [s for s in (b'proc_pidinfo', b'proc_listpids') if s in binary_data]
    if proc_refs:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'PROC_INFO_ENUMERATION',
            'detail': (
                'Binary references {} — process surveillance API; '
                'maps running process list for targeting or evasion'
            ).format(', '.join(r.decode() for r in proc_refs)),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_shellcode_patterns(binary_data: bytes) -> list:
    """
    Detect shellcode techniques in binary data.
    Synthesized from: Practical Malware Analysis (Sikorski & Honig) — Chapter 19 Shellcode Analysis,
    Position-Independent Code, Finding Shellcode, NOP Sleds, Shellcode Encodings.

    Checks:
    - CALL/POP position-independent EIP recovery (E8 followed within 5 bytes by POP 58-5F)
    - FPU FSTENV/FNSTENV GetPC stub: fldz (D9 EE) + fnstenv [esp-N] (D9 74 24) recovers EIP
      via fpu_instruction_pointer field at offset +12 of FpuSaveState structure
    - NOP sled: 16+ consecutive 0x90 bytes preceding shellcode as exploit landing pad
    - Egg hunter pattern: 66 81 CA FF 0F (OR DX,0x0FFF Skape page-walker prologue) signals
      a two-stage shellcode where the hunter scans VA space for a repeated 4-byte egg tag
    - Null-free shellcode candidate: 64+ byte run with no 0x00 bytes and probable x86 starters,
      satisfying strcpy/strcat buffer overflow filter constraints

    Args:
        binary_data: raw bytes to scan

    Returns:
        list of {severity, title, detail, host, port}
    """
    findings = []

    if not binary_data:
        return findings

    # --- CALL/POP PIC technique ---
    # E8 (CALL rel32) followed within 5 bytes by POP register (58-5F).
    # Primary form: E8 00 00 00 00 5x (call $+5; pop reg) — processor pushes EIP of next
    # instruction onto stack; immediate POP loads that address into a general-purpose register
    # for use as a base pointer for all subsequent position-independent data access.
    # Reference: PMA ch19 "Identifying Execution Location" / call/pop Hello World example.
    pop_opcodes = frozenset(range(0x58, 0x60))  # POP EAX(58)..EDI(5F)
    call_pop_hits = []
    for i in range(len(binary_data) - 5):
        if binary_data[i] == 0xE8:
            for b in binary_data[i + 1:i + 6]:
                if b in pop_opcodes:
                    call_pop_hits.append(i)
                    break
    if call_pop_hits:
        findings.append({
            'severity': 'HIGH',
            'title': 'CALL_POP_PIC',
            'detail': (
                f'Position-independent shellcode technique — CALL (0xE8) followed by POP (0x58-0x5F) '
                f'at {len(call_pop_hits)} offset(s); shellcode pushes EIP via CALL then immediately '
                'POPs it into a register to establish a base pointer for EIP-relative data access '
                'without a direct MOV EAX,EIP instruction (unavailable on x86)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- FPU FSTENV/FNSTENV GetPC stub ---
    # fldz (D9 EE) primes the FPU so fpu_instruction_pointer is updated; fnstenv (D9 74 24 ...)
    # stores the 28-byte FpuSaveState to the stack — field at offset +12 holds the address of
    # the last FPU instruction (fldz), giving shellcode its runtime EIP equivalent via POP.
    # Reference: PMA ch19 Example 19-3 fnstenv Hello World; FpuSaveState structure layout.
    fstenv_patterns = [
        b'\xD9\xEE\xD9\x74\x24',       # fldz; fnstenv [esp-N] (generic, N varies)
        b'\xD9\xEE\xD9\x74\x24\xF4',   # exact PMA book example: fnstenv [esp-0Ch]
        b'\xD9\xD0\xD9\x74\x24',       # fnop + fnstenv variant (alternate FPU primer)
    ]
    fstenv_hits = set()
    for pat in fstenv_patterns:
        offset = 0
        while True:
            idx = binary_data.find(pat, offset)
            if idx == -1:
                break
            fstenv_hits.add(idx)
            offset = idx + 1

    if fstenv_hits:
        findings.append({
            'severity': 'HIGH',
            'title': 'FSTENV_GETPC',
            'detail': (
                f'FPU-based shellcode PC recovery at {len(fstenv_hits)} location(s) — '
                'fldz/fnop primes FPU instruction pointer; fnstenv stores FpuSaveState (28 bytes) '
                'to stack; shellcode POPs fpu_instruction_pointer (offset +12) as runtime EIP; '
                'evades disassemblers that interpret the data following the stub as code'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- NOP sled ---
    # 16+ consecutive 0x90 bytes: exploit landing pad that tolerates imprecise EIP control.
    # As long as execution lands anywhere in the sled, it slides into the shellcode.
    # Exploit authors also use 0x40-0x4F (INC/DEC reg) as "polymorphic NOPs" to evade
    # signature detection while keeping bytes printable ASCII.
    # Reference: PMA ch19 "NOP Sleds".
    NOP_THRESHOLD = 16
    nop_runs = []
    i = 0
    while i < len(binary_data):
        if binary_data[i] == 0x90:
            start = i
            while i < len(binary_data) and binary_data[i] == 0x90:
                i += 1
            run_len = i - start
            if run_len >= NOP_THRESHOLD:
                nop_runs.append((start, run_len))
        else:
            i += 1

    if nop_runs:
        longest = max(nop_runs, key=lambda x: x[1])
        findings.append({
            'severity': 'HIGH',
            'title': 'NOP_SLED',
            'detail': (
                f'Buffer overflow shellcode landing pad — {len(nop_runs)} NOP sled(s) of '
                f'>={NOP_THRESHOLD} bytes; longest: {longest[1]} bytes at offset 0x{longest[0]:x}; '
                'execution directed anywhere in the sled slides into the shellcode payload; '
                'increases exploit reliability when precise EIP redirection is unavailable'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- Egg hunter pattern ---
    # Skape egg hunter page-walking prologue: OR DX,0x0FFF (66 81 CA FF 0F) aligns DX to the
    # next page boundary on each iteration, then INC EDX steps through the VA space searching
    # for a repeated 4-byte "egg" tag that marks the start of the full shellcode payload.
    # Used when exploit buffer space is too small for full shellcode — the hunter is tiny
    # (~32 bytes) and the main stage can be placed anywhere in process memory first.
    # Reference: PMA ch19 "Finding Shellcode"; Skape "Safely Searching Process Virtual Address Space".
    egg_hunter_patterns = [
        b'\x66\x81\xCA\xFF\x0F',       # or dx, 0x0fff — canonical Skape page-walker
        b'\x66\x81\xCA\xFF\x0F\x42',   # + inc edx (common continuation byte)
    ]
    egg_hits = set()
    for pat in egg_hunter_patterns:
        offset = 0
        while True:
            idx = binary_data.find(pat, offset)
            if idx == -1:
                break
            egg_hits.add(idx)
            offset = idx + 1

    if egg_hits:
        findings.append({
            'severity': 'HIGH',
            'title': 'EGG_HUNTER_PATTERN',
            'detail': (
                f'Small staged shellcode loader — egg hunter page-walker at {len(egg_hits)} '
                'location(s); OR DX,0x0FFF advances through process VA space page-by-page '
                'searching for a repeated 4-byte egg tag that precedes the main shellcode stage; '
                'indicates two-stage delivery where the full payload was placed separately before exploit'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- Null-free shellcode candidate ---
    # Shellcode exploiting strcpy/strcat/gets must contain no 0x00 bytes, since these functions
    # treat NULL as a string terminator. Authors rework instructions to avoid embedded NULLs
    # (e.g. XOR EAX,EAX instead of MOV EAX,0; PUSH BYTE 1 instead of PUSH DWORD 1).
    # Heuristic: 64+ byte region with no 0x00 and first byte in common x86 instruction starters.
    # Reference: PMA ch19 "Shellcode Encodings" — null-free constraint and encoding rationale.
    NULL_FREE_WINDOW = 64
    x86_starters = frozenset([
        0x55, 0x56, 0x57, 0x53,          # PUSH reg (prologue pattern)
        0x89, 0x8B, 0x8D, 0x8A,          # MOV/LEA variants
        0xFF, 0xE8, 0xEB, 0xE9,          # CALL / JMP
        0x31, 0x33, 0x83, 0x85, 0x81,    # XOR / AND / TEST / OR
        0x50, 0x51, 0x52, 0x58, 0x59,    # PUSH/POP
        0x90, 0xB8, 0xBF, 0xBE, 0xBB,   # NOP / MOV reg,imm32
        0x6A, 0x68,                       # PUSH imm8 / imm32
    ])
    null_free_regions = 0
    i = 0
    while i <= len(binary_data) - NULL_FREE_WINDOW:
        window = binary_data[i:i + NULL_FREE_WINDOW]
        if b'\x00' not in window and window[0] in x86_starters:
            null_free_regions += 1
            i += NULL_FREE_WINDOW
        else:
            i += 1

    if null_free_regions > 0:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'NULL_FREE_SHELLCODE_CANDIDATE',
            'detail': (
                f'{null_free_regions} null-free region(s) of {NULL_FREE_WINDOW}+ bytes with '
                'probable x86 instruction starters — satisfies strcpy/strcat/gets filter bypass; '
                'shellcode authors eliminate 0x00 bytes (e.g. "push 1" over "mov eax,1"; '
                '"xor eax,eax" over "mov eax,0") to survive string-based copy into vulnerable buffer'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_process_hollowing(binary_data: bytes) -> list:
    """
    Detect process hollowing / replacement indicators in binary data.
    Synthesized from: Practical Malware Analysis (Sikorski & Honig) — Chapter 12 Process Replacement,
    Process Injection; Chapter 7 Native API (ZwUnmapViewOfSection).

    Process hollowing (replacement) sequence:
      CreateProcess(CREATE_SUSPENDED) -> ZwUnmapViewOfSection (unmaps legitimate image) ->
      VirtualAllocEx + WriteProcessMemory (maps malicious PE sections) ->
      SetThreadContext (redirects entry point) -> ResumeThread (executes injected code).
    Masquerades malware as a legitimate process (e.g. svchost.exe) — process listing shows
    the original binary path while executing attacker-controlled code.

    Checks:
    - CreateProcess + NtUnmapViewOfSection/ZwUnmapViewOfSection: classic image replacement
    - WriteProcessMemory + SetThreadContext + ResumeThread: hollow injection finish sequence
    - VirtualAllocEx + WriteProcessMemory: cross-process remote memory write primitive
    - CREATE_SUSPENDED string: suspended process creation — prerequisite for hollowing

    Args:
        binary_data: raw bytes to scan

    Returns:
        list of {severity, title, detail, host, port}
    """
    findings = []

    if not binary_data:
        return findings

    # --- CreateProcess + NtUnmapViewOfSection/ZwUnmapViewOfSection ---
    # Core process replacement pair: spawn target process suspended, unmap its image via the
    # Native API (Nt/Zw prefix functions bypass Win32 layer — attractive for AV evasion since
    # poorly designed products monitor kernel32 not ntdll). Then allocate and write the malicious
    # PE. Reference: PMA ch12 Example 12-3; ch7 "The Native API" (Nt == Zw in user space).
    create_process_variants = [b'CreateProcessA', b'CreateProcessW', b'CreateProcess']
    unmap_variants = [b'NtUnmapViewOfSection', b'ZwUnmapViewOfSection']

    has_create_process = any(v in binary_data for v in create_process_variants)
    unmap_found = [v.decode() for v in unmap_variants if v in binary_data]

    if has_create_process and unmap_found:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'PROCESS_HOLLOWING',
            'detail': (
                f'Classic process replacement — CreateProcess + {unmap_found[0]}; '
                'malware spawns a legitimate process suspended, calls ZwUnmapViewOfSection '
                '(Native API — ntdll, not kernel32) to release the original image sections, '
                'then injects a malicious PE; victim process list shows legitimate binary path '
                'while executing attacker code (common target: svchost.exe)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- WriteProcessMemory + SetThreadContext + ResumeThread sequence ---
    # Three-step injection finish: write each malicious PE section into the unmapped process,
    # redirect the suspended thread's entry point via SetThreadContext (modifies CONTEXT.Eip),
    # then call ResumeThread to begin execution of the injected payload.
    # Reference: PMA ch12 Example 12-3 pseudocode: WriteProcessMemory loop -> SetThreadContext -> ResumeThread.
    wpm_present = b'WriteProcessMemory' in binary_data
    stc_present = b'SetThreadContext' in binary_data
    rt_present = b'ResumeThread' in binary_data

    if wpm_present and stc_present and rt_present:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'PROCESS_INJECTION_SEQUENCE',
            'detail': (
                'Hollow process code injection — WriteProcessMemory + SetThreadContext + ResumeThread '
                'all present; attacker writes malicious PE sections into unmapped victim process, '
                'sets suspended thread entry point (CONTEXT.Eip) via SetThreadContext, '
                'then calls ResumeThread to execute injected payload'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- VirtualAllocEx + WriteProcessMemory ---
    # Foundation primitive for both DLL injection and direct shellcode injection into a remote
    # process. VirtualAllocEx allocates executable memory in the victim's address space;
    # WriteProcessMemory writes the payload (shellcode, DLL name, or PE sections).
    # Reference: PMA ch12 "Process Injection" / "Direct Injection"; ch12 Example 12-1.
    vae_present = b'VirtualAllocEx' in binary_data

    if vae_present and wpm_present:
        findings.append({
            'severity': 'HIGH',
            'title': 'REMOTE_PROCESS_WRITE',
            'detail': (
                'Cross-process memory write — VirtualAllocEx + WriteProcessMemory; '
                'allocates executable memory in a remote process and writes arbitrary payload; '
                'foundation for DLL injection (write DLL name -> CreateRemoteThread(LoadLibrary)), '
                'direct shellcode injection, and process replacement section writes'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- CREATE_SUSPENDED string ---
    # dwCreationFlags=0x4 (CREATE_SUSPENDED) passed to CreateProcess: loads the target process
    # into memory but suspends the primary thread at the entry point before any code runs.
    # Attacker has a clean window to unmap the image and install the malicious payload.
    # Reference: PMA ch12 "Process Replacement" / Example 12-2 assembly (push CREATE_SUSPENDED).
    if b'CREATE_SUSPENDED' in binary_data:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SUSPENDED_PROCESS_CREATION',
            'detail': (
                'CREATE_SUSPENDED string found — process created with dwCreationFlags=0x4; '
                'primary thread suspended at entry point before execution; '
                'standard setup step for process hollowing: attacker unmaps and replaces the '
                'image before calling ResumeThread, ensuring the victim process never runs its '
                'own legitimate code'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def probe_smb_exposure(host: str, timeout: float = 10.0) -> list:
    import socket
    import struct

    findings = []

    # --- Port 445: SMB direct hosting ---
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 445))
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SMB_PORT_EXPOSED',
            'detail': 'SMB port directly accessible (lateral movement, ransomware risk)',
            'host': host,
            'port': 445,
        })

        # SMB2 Negotiate Request:
        # 4-byte NetBIOS session header + SMB2 header (64 bytes) + negotiate body
        # SMB2 header: ProtocolId=\xfeSMB, StructureSize=64, CreditCharge=0,
        #   Status=0, Command=0x0000 (NEGOTIATE), CreditRequest=1, Flags=0,
        #   NextCommand=0, MessageId=1, Reserved=0, TreeId=0, SessionId=0, Signature=16x\x00
        smb2_header = struct.pack(
            '<4sHHIHHIIIII16s',
            b'\xfeSMB',   # ProtocolId
            64,            # StructureSize
            0,             # CreditCharge
            0,             # Status
            0x0000,        # Command: NEGOTIATE
            1,             # CreditRequest
            0,             # Flags
            0,             # NextCommand
            1,             # MessageId (low)
            0,             # MessageId (high) -- split as two 32-bit for simplicity
            0,             # Reserved + TreeId packed
            0,             # SessionId (low)
        )
        # Build a proper 64-byte SMB2 header manually to avoid struct complexity
        smb2_hdr = (
            b'\xfeSMB'           # ProtocolId
            + b'\x40\x00'        # StructureSize = 64
            + b'\x00\x00'        # CreditCharge
            + b'\x00\x00\x00\x00'  # Status
            + b'\x00\x00'        # Command: NEGOTIATE
            + b'\x01\x00'        # CreditRequest
            + b'\x00\x00\x00\x00'  # Flags
            + b'\x00\x00\x00\x00'  # NextCommand
            + b'\x01\x00\x00\x00\x00\x00\x00\x00'  # MessageId
            + b'\x00\x00\x00\x00'  # Reserved
            + b'\x00\x00\x00\x00'  # TreeId
            + b'\x00\x00\x00\x00\x00\x00\x00\x00'  # SessionId
            + b'\x00' * 16       # Signature
        )
        # SMB2 NEGOTIATE body: StructureSize=36, DialectCount=1, SecurityMode=1,
        #   Reserved=0, Capabilities=0, ClientGuid=16x\x00, ClientStartTime=0,
        #   Dialects=[0x0300]
        negotiate_body = (
            b'\x24\x00'          # StructureSize = 36
            + b'\x01\x00'        # DialectCount = 1
            + b'\x01\x00'        # SecurityMode: signing enabled
            + b'\x00\x00'        # Reserved
            + b'\x00\x00\x00\x00'  # Capabilities
            + b'\x00' * 16       # ClientGuid
            + b'\x00\x00\x00\x00\x00\x00\x00\x00'  # ClientStartTime
            + b'\x00\x03'        # Dialect: SMB 3.0
        )
        payload = smb2_hdr + negotiate_body
        # NetBIOS session header: type=0x00, length (3 bytes big-endian)
        nb_header = b'\x00' + struct.pack('>I', len(payload))[1:]
        s.sendall(nb_header + payload)

        response = b''
        try:
            while len(response) < 4:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            if len(response) >= 4:
                nb_len = struct.unpack('>I', b'\x00' + response[1:4])[0]
                while len(response) < 4 + nb_len:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
        except socket.timeout:
            pass

        smb2_body = response[4:] if len(response) > 4 else b''

        # Check SMB2 response magic
        if smb2_body[:4] == b'\xfeSMB':
            findings.append({
                'severity': 'HIGH',
                'title': 'SMB2_NEGOTIATED',
                'detail': 'SMB2 protocol negotiated',
                'host': host,
                'port': 445,
            })
            # SecurityMode is at offset 14 in the SMB2 header (2 bytes)
            # Bit 1 (0x02) = SMB2_NEGOTIATE_SIGNING_REQUIRED
            if len(smb2_body) >= 16:
                security_mode = struct.unpack('<H', smb2_body[14:16])[0]
                signing_required = bool(security_mode & 0x02)
                if not signing_required:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'SMB_SIGNING_NOT_REQUIRED',
                        'detail': (
                            'SMB signing not enforced (NTLM relay attack possible) — '
                            'SecurityMode bit 1 not set; connections accepted without signing; '
                            'attacker can relay NTLM authentication to this host'
                        ),
                        'host': host,
                        'port': 445,
                    })

        s.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    # --- Port 139: NetBIOS SMB ---
    try:
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(timeout)
        s2.connect((host, 139))
        s2.close()
        findings.append({
            'severity': 'MEDIUM',
            'title': 'NETBIOS_SMB_EXPOSED',
            'detail': 'Legacy NetBIOS SMB port accessible',
            'host': host,
            'port': 139,
        })
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return findings


def detect_ntlm_relay_surface(binary_data: bytes) -> list:
    import re

    findings = []

    # --- NTLMSSP signature ---
    # The 8-byte NTLMSSP\x00 magic present in all NTLM messages (Type 1/2/3).
    # Its presence in a binary means the binary implements or embeds NTLM auth;
    # relay tools look for this to identify negotiation targets.
    if b'NTLMSSP\x00' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title': 'NTLMSSP_IMPLEMENTATION',
            'detail': (
                'NTLM authentication implementation present — '
                'NTLMSSP\\x00 magic found; binary participates in NTLM negotiation; '
                'relay tools can intercept and forward NTLM challenge/response sequences'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- NtLmSsp + AcceptSecurityContext: server-side NTLM ---
    # AcceptSecurityContext is the SSPI call used by NTLM servers to validate
    # incoming NTLM Type-3 (Authenticate) messages.  Its co-presence with the
    # NTLM provider name identifies a relay *target* rather than a client.
    has_ntlmssp_str = b'NtLmSsp' in binary_data
    has_accept_sec  = b'AcceptSecurityContext' in binary_data
    if has_ntlmssp_str and has_accept_sec:
        findings.append({
            'severity': 'HIGH',
            'title': 'NTLM_SERVER_ACCEPT',
            'detail': (
                'NTLM server-side authentication (relay target potential) — '
                'NtLmSsp provider string + AcceptSecurityContext indicate this binary '
                'acts as an NTLM server; relay attacks forward captured credentials here '
                'to authenticate as the victim'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- NTLMv1 weak auth indicators ---
    # NTLMv1 LM response is exactly 24 bytes of DES applied to the NT hash.
    # Detect either the literal LM response length sentinel or the NtChallengeResponse
    # offset pattern characteristic of Type-3 NTLMv1 messages in binary blobs.
    # Pattern: LmChallengeResponseLen=24 (0x18 0x00) immediately followed by
    # LmChallengeResponseMaxLen=24 (0x18 0x00) — the NTLMSSP Type-3 field layout.
    ntlmv1_lm_pattern = re.compile(b'\x18\x00\x18\x00')
    # Also flag the string "LM Response" or "NTLMv1" literally compiled in
    has_lm_response_str = b'LM Response' in binary_data or b'NTLMv1' in binary_data
    if ntlmv1_lm_pattern.search(binary_data) or has_lm_response_str:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'NTLM_V1_USAGE',
            'detail': (
                'NTLMv1 hash in binary (crackable offline, relay-able) — '
                'LM response 24-byte sentinel or NTLMv1 string detected; '
                'NTLMv1 responses can be cracked in seconds on modern hardware '
                'and relay directly to services that accept NTLMv1 downgrade'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- Pass-the-hash API sequence ---
    # LsaLogonUser combined with a buffer suggestive of NT hash material (NtHashBuffer,
    # NtHash, or the KERB_INTERACTIVE_UNLOCK_LOGON / MSV1_0_INTERACTIVE_LOGON structs
    # which embed the NT hash directly) indicates PTH capability.
    has_lsa_logon    = b'LsaLogonUser' in binary_data
    has_hash_buffer  = (
        b'NtHashBuffer' in binary_data
        or b'NtHash' in binary_data
        or b'MSV1_0_INTERACTIVE_LOGON' in binary_data
        or b'KERB_INTERACTIVE_UNLOCK_LOGON' in binary_data
    )
    if has_lsa_logon and has_hash_buffer:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'PASS_THE_HASH_PATTERN',
            'detail': (
                'NTLM pass-the-hash API sequence detected — '
                'LsaLogonUser + NT hash buffer structure; binary can authenticate '
                'using a raw NT hash without knowing the plaintext password; '
                'standard lateral-movement primitive enabling impersonation across '
                'all hosts sharing the same local admin hash'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def probe_bacnet_exposure(host: str, port: int = 47808, timeout: float = 5.0) -> list:
    """Probe BACnet building automation controller for unauthenticated exposure."""
    import socket
    import struct

    findings = []

    # BACnet Who-Is request (BVLC encapsulated NPDU + APDU)
    who_is = b'\x81\x0b\x00\x08\x01\x20\xff\xff\x00\xff\x10\x08'

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(who_is, (host, port))

        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            data = None

        if data and len(data) >= 4 and data[0] == 0x81 and data[1] in (0x0b, 0x10):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'BACNET_UNAUTH',
                'detail': (
                    'BACnet building automation controller responding without authentication — '
                    'I-Am response received to unauthenticated Who-Is broadcast; '
                    'BACnet/IP has no native authentication; exposes HVAC, access control, '
                    'fire suppression, and power systems to unauthenticated enumeration and control'
                ),
                'host': host,
                'port': port,
            })

            # Parse I-Am response for device ID and vendor
            # APDU starts after BVLC (4 bytes) + NPDU (variable); minimal parse
            try:
                # Locate APDU PDU-type 0x10 (Unconfirmed-REQ) + service 0x00 (I-Am)
                # I-Am payload: Object-Identifier (tag 0, class 0) + max APDU + segmentation + vendor ID
                apdu_offset = None
                for i in range(4, len(data) - 2):
                    if data[i] == 0x10 and data[i + 1] == 0x00:
                        apdu_offset = i + 2
                        break

                if apdu_offset is not None and apdu_offset + 7 <= len(data):
                    # Object-Identifier tag: tag 0, length 4 -> encoded as 0x0C
                    if data[apdu_offset] == 0x0C and apdu_offset + 5 <= len(data):
                        raw_oid = struct.unpack('>I', data[apdu_offset + 1:apdu_offset + 5])[0]
                        device_id = raw_oid & 0x3FFFFF
                        # Vendor ID is last 2 bytes of I-Am (tag 3, uint)
                        # Search for tag 0x21 (context 3, uint) or tag 0x22 near end
                        vendor_id = None
                        for j in range(apdu_offset + 5, len(data) - 1):
                            if data[j] in (0x21, 0x22):
                                if data[j] == 0x21 and j + 1 < len(data):
                                    vendor_id = data[j + 1]
                                elif data[j] == 0x22 and j + 2 < len(data):
                                    vendor_id = struct.unpack('>H', data[j + 1:j + 3])[0]
                                break
                        vendor_str = str(vendor_id) if vendor_id is not None else 'unknown'
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'BACNET_DEVICE_DISCLOSED',
                            'detail': (
                                f'BACnet device ID {device_id} and vendor {vendor_str} disclosed — '
                                'device object identifier exposed without authentication; '
                                'device ID enables targeted ReadProperty/WriteProperty attacks; '
                                'vendor ID maps to specific product lines with known CVEs'
                            ),
                            'host': host,
                            'port': port,
                        })
            except (struct.error, IndexError):
                pass

            # ReadProperty: device object (type 8, instance = device_id from above or 0),
            # property 77 (objectName), array-index omitted
            # BVLC + NPDU + APDU ReadProperty confirmed-request
            try:
                dev_inst = device_id if 'device_id' in dir() else 0  # noqa: F821
                # Encode device instance into Object-Identifier (type 8 = device, 22 bits)
                obj_id_val = (8 << 22) | (dev_inst & 0x3FFFFF)
                apdu_rp = (
                    b'\x00'          # PDU-type: confirmed-request, no seg, max segs 0
                    b'\x05'          # max APDU size: 1476
                    b'\x01'          # invoke-id
                    b'\x0c'          # service: ReadProperty
                    + b'\x0c'        # context tag 0, length 4 (object-identifier)
                    + struct.pack('>I', obj_id_val)
                    + b'\x19'        # context tag 1, length 1 (property-identifier)
                    + b'\x4d'        # 77 = objectName
                )
                npdu = b'\x01\x04'   # version 1, expecting reply
                bvlc_len = 4 + len(npdu) + len(apdu_rp)
                bvlc = struct.pack('>BBH', 0x81, 0x0a, bvlc_len)  # 0x0a = unicast
                pkt = bvlc + npdu + apdu_rp

                sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock2.settimeout(timeout)
                sock2.sendto(pkt, (host, port))
                try:
                    rp_data, _ = sock2.recvfrom(4096)
                    # Complex-ACK (0x30) or any non-error response indicates readable
                    if rp_data and len(rp_data) >= 4 and rp_data[4] in (0x30, 0x10):
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'BACNET_OBJECT_READ_UNAUTH',
                            'detail': (
                                'BACnet object properties readable without authentication — '
                                'ReadProperty for objectName (property 77) on device object returned data; '
                                'unauthenticated property reads expose device configuration, '
                                'schedule objects, and control points; WriteProperty likely also unprotected'
                            ),
                            'host': host,
                            'port': port,
                        })
                except socket.timeout:
                    pass
                finally:
                    sock2.close()
            except (struct.error, OSError):
                pass

    except OSError:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return findings


def probe_ethernet_ip_exposure(host: str, port: int = 44818, timeout: float = 5.0) -> list:
    """Probe EtherNet/IP industrial protocol port for unauthenticated exposure."""
    import socket
    import struct

    findings = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        findings.append({
            'severity': 'HIGH',
            'title': 'ETHERNET_IP_PORT_OPEN',
            'detail': (
                'EtherNet/IP industrial protocol port accessible — '
                'TCP 44818 accepted connection; EtherNet/IP is the primary protocol '
                'for Allen-Bradley/Rockwell PLCs and many Omron, Schneider, and Siemens devices; '
                'exposure of this port to untrusted networks violates ICS network segmentation baselines '
                '(IEC 62443, NIST SP 800-82)'
            ),
            'host': host,
            'port': port,
        })

        # EtherNet/IP ListIdentity: command 0x0063, length 0x0000, session 0x00000000
        # + options and sender context padding to reach 24-byte encapsulation header
        list_identity = struct.pack('<HHI', 0x0063, 0x0000, 0x00000000) + b'\x00' * 16

        sock.sendall(list_identity)
        sock.settimeout(timeout)

        try:
            resp = b''
            while len(resp) < 24:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk

            if len(resp) >= 24:
                cmd, length, session = struct.unpack_from('<HHI', resp, 0)
                if cmd == 0x0065 or (cmd == 0x0063 and length > 0):
                    # Response carries identity item(s)
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'ETHERNET_IP_LIST_IDENTITY',
                        'detail': (
                            'EtherNet/IP ListIdentity succeeded (PLC vendor, product code, serial number disclosed) — '
                            'device returned identity object without session establishment or authentication; '
                            'response contains vendor ID, device type, product code, revision, serial number, '
                            'and product name; enables targeted exploitation of known firmware CVEs '
                            'and precise PLC model fingerprinting for CIP-layer attacks'
                        ),
                        'host': host,
                        'port': port,
                    })
        except socket.timeout:
            pass

        # CIP Read Tag Service (0x4C) — attempt read of common tag names
        # EtherNet/IP encapsulated CIP Unconnected Send via SendRRData (0x0065)
        # Minimal CIP path: symbolic segment for tag "Program:MainProgram"
        try:
            tag_name = b'Program:MainProgram'
            tag_len = len(tag_name)
            # Pad to even byte count
            padded = tag_name + (b'\x00' if tag_len % 2 else b'')
            symbolic_segment = bytes([0x91, tag_len]) + padded

            # CIP Read Tag request: service 0x4C, path
            cip_path_size = (len(symbolic_segment) + 1) // 2  # in words
            cip_req = bytes([
                0x4C,           # Read Tag service
                cip_path_size,  # path size in words
            ]) + symbolic_segment + struct.pack('<H', 1)  # count=1

            # CPF: Null address item (0x0000, len 0) + Unconnected Data item (0x00B2)
            cpf = (
                struct.pack('<HH', 0x0000, 0x0000)  # null address
                + struct.pack('<HH', 0x00B2, len(cip_req))
                + cip_req
            )

            # Encapsulation header for SendRRData (0x0065)
            timeout_ticks = struct.pack('<I', 10)
            send_rr_data = timeout_ticks + cpf
            enc_header = struct.pack('<HHI', 0x0065, len(send_rr_data), session) + b'\x00' * 16
            pkt = enc_header + send_rr_data

            sock.sendall(pkt)
            sock.settimeout(timeout)

            try:
                cip_resp = b''
                while len(cip_resp) < 24:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    cip_resp += chunk

                if len(cip_resp) >= 24:
                    resp_cmd = struct.unpack_from('<H', cip_resp, 0)[0]
                    # General status 0x00 = success, 0x08 = path segment error (tag exists, auth issue)
                    if resp_cmd == 0x0065 and len(cip_resp) > 44:
                        gen_status_offset = 44  # after enc header (24) + timeout (4) + CPF addr (4) + CPF data hdr (4) + reply svc (1) + reserved (1) + gen_status
                        gen_status = cip_resp[gen_status_offset] if gen_status_offset < len(cip_resp) else 0xFF
                        if gen_status in (0x00, 0x08, 0x26):
                            findings.append({
                                'severity': 'CRITICAL',
                                'title': 'ETHERNET_IP_CIP_UNAUTH',
                                'detail': (
                                    'CIP read tag service accepts unauthenticated requests — '
                                    'Read Tag (0x4C) CIP service returned non-reject status without '
                                    'prior session authentication; unauthenticated CIP allows reading '
                                    'and potentially writing PLC controller tags, enabling manipulation '
                                    'of process setpoints, output states, and safety interlocks'
                                ),
                                'host': host,
                                'port': port,
                            })
            except socket.timeout:
                pass

        except (struct.error, OSError):
            pass

    except OSError:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return findings


def detect_exploit_socket_patterns(binary_data: bytes, host: str = '', port: int = 0) -> list:
    """Detect network exploitation socket patterns in compiled binaries.

    Inspects binary content for socket API usage patterns characteristic of
    reverse shells, bind shells, raw socket creation, and other exploitation
    techniques documented in Hacking: The Art of Exploitation (Ch. 0x400).
    Returns List[dict] with keys: severity, title, detail, host, port.
    """
    findings = []

    def _sym(data: bytes, name: bytes) -> bool:
        """Check whether a symbol name appears in the binary data."""
        return name in data

    # -- 1. Raw socket usage: SOCK_RAW=3, AF_PACKET, or AF_RAW strings ----------------------
    # AoE Ch. 0x400: SOCK_RAW bypasses kernel TCP/IP stack for custom packet construction
    sock_raw_present = False
    if b'AF_PACKET' in binary_data or b'AF_RAW' in binary_data:
        sock_raw_present = True
    if _sym(binary_data, b'socket') and (
        re.search(rb'(?:PF_INET|AF_INET|SOCK_RAW)', binary_data)
        or b'\x03\x00\x00\x00' in binary_data  # SOCK_RAW=3 as LE int32
    ):
        sock_raw_present = True
    if sock_raw_present:
        findings.append({
            'severity': 'HIGH',
            'title': 'RAW_SOCKET_USAGE',
            'detail': (
                'Binary references raw socket creation (SOCK_RAW=3 or AF_PACKET/AF_RAW). '
                'Raw sockets bypass the kernel TCP/IP stack enabling custom packet '
                'construction, network sniffing without libpcap, and spoofed packet '
                'injection — common in exploitation frameworks and custom C2 implants '
                '(AoE Ch. 0x400 network sniffing section).'
            ),
            'host': host,
            'port': port,
        })

    # -- 2. IP_HDRINCL raw packet injection: IP_HDRINCL=3 + IPPROTO_RAW=255 ----------------
    # IP_HDRINCL lets the caller supply IP headers directly in raw sockets;
    # IPPROTO_RAW=255 as third socket() arg creates a fully controllable raw socket
    ipproto_raw_le = b'\xff\x00\x00\x00'   # 255 as LE int32
    ip_hdrincl_le  = b'\x03\x00\x00\x00'   # 3  as LE int32
    if (
        _sym(binary_data, b'socket')
        and ipproto_raw_le in binary_data
        and (b'IP_HDRINCL' in binary_data or ip_hdrincl_le in binary_data)
    ):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'IP_RAW_HEADER_INJECTION',
            'detail': (
                'Binary references IPPROTO_RAW (255) and IP_HDRINCL (3) — caller-supplied '
                'IP header pattern. Full control over IP header fields including source '
                'address spoofing, TTL manipulation, and arbitrary protocol numbers. '
                'Common in DoS tools, covert channel implants, and ICMP/UDP tunneling '
                '(AoE Ch. 0x400 raw socket / DoS sections).'
            ),
            'host': host,
            'port': port,
        })

    # -- 3. Reverse shell: socket + connect + dup2 + execve ---------------------------------
    # AoE Ch. 0x400/0x500: socket() creates fd, connect() reaches C2, dup2(fd,0/1/2)
    # redirects stdin/stdout/stderr, execve("/bin/sh") spawns the shell
    has_socket  = b'socket'  in binary_data
    has_connect = b'connect' in binary_data
    has_dup2    = b'dup2'    in binary_data
    has_execve  = (b'execve' in binary_data
                   or b'/bin/sh'   in binary_data
                   or b'/bin/bash' in binary_data)

    if has_socket and has_connect and has_dup2 and has_execve:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'REVERSE_SHELL_SOCKET_PATTERN',
            'detail': (
                'Binary contains socket()+connect()+dup2()+execve() symbol cluster — '
                'canonical reverse shell pattern (AoE Ch. 0x400/0x500 connect-back shellcode). '
                'dup2() redirects stdin/stdout/stderr to the socket fd; execve() launches '
                'a shell over the connection. Attacker controls the remote C2 endpoint.'
            ),
            'host': host,
            'port': port,
        })

    # -- 4. Bind shell: socket + bind + listen + accept + execve ----------------------------
    # AoE Ch. 0x500 port-binding shellcode: listener accepts inbound connections and
    # exec()s a shell — no outbound C2 traffic generated
    has_bind   = b'bind'   in binary_data
    has_listen = b'listen' in binary_data
    has_accept = b'accept' in binary_data

    if has_socket and has_bind and has_listen and has_accept and has_execve:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'BIND_SHELL_SOCKET_PATTERN',
            'detail': (
                'Binary contains socket()+bind()+listen()+accept()+execve() symbol cluster — '
                'canonical bind shell pattern (AoE Ch. 0x500 port-binding shellcode). '
                'Process listens on a port and spawns a shell to any connecting client; '
                'no outbound C2 traffic. Attacker connects inbound to the listening port.'
            ),
            'host': host,
            'port': port,
        })

    # -- 5. Socket port reuse: setsockopt(SO_REUSEADDR/SO_REUSEPORT) + bind -----------------
    # AoE simple_server.c uses SO_REUSEADDR so the server can rebind after crash/restart;
    # in implants this allows stealth binding to ports held by legitimate services
    so_reuseaddr_le = b'\x02\x00\x00\x00'   # SO_REUSEADDR=2 as LE int32
    so_reuseport_le = b'\x0f\x00\x00\x00'   # SO_REUSEPORT=15 as LE int32
    has_setsockopt  = b'setsockopt' in binary_data
    has_reuseaddr   = b'SO_REUSEADDR' in binary_data or so_reuseaddr_le in binary_data
    has_reuseport   = b'SO_REUSEPORT' in binary_data or so_reuseport_le in binary_data

    if has_setsockopt and (has_reuseaddr or has_reuseport) and has_bind:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SOCKET_REUSE_BINDING',
            'detail': (
                'Binary uses setsockopt(SO_REUSEADDR/SO_REUSEPORT) combined with bind() — '
                'port reuse pattern from AoE simple_server.c. Legitimate in servers but in '
                'implants enables binding to ports already held by services, facilitating '
                'port-knocking evasion, stealth bind shells, and hijacking of well-known ports.'
            ),
            'host': host,
            'port': port,
        })

    # -- 6. Connectionless data exfil: sendto() without prior connect() ---------------------
    # AoE Ch. 0x400 datagram sockets: sendto() addresses each UDP packet individually,
    # avoiding TCP handshake state in firewall logs — DNS/UDP-based exfil pattern
    has_sendto = b'sendto' in binary_data

    if has_sendto and not has_connect:
        findings.append({
            'severity': 'HIGH',
            'title': 'CONNECTIONLESS_DATA_SEND',
            'detail': (
                'Binary uses sendto() without connect() — UDP datagram exfiltration pattern '
                '(AoE Ch. 0x400 SOCK_DGRAM section). Each packet addressed individually, '
                'avoiding TCP handshake state in firewall logs. Common in DNS-based C2, '
                'UDP data exfiltration, and covert channels that evade TCP session tracking.'
            ),
            'host': host,
            'port': port,
        })

    # -- 7. Async socket multiplexing: fcntl(F_SETFL, O_NONBLOCK) + select/poll/epoll ------
    # AoE port scanning: non-blocking I/O + select() allows single-threaded probing of
    # thousands of hosts rapidly without per-connection blocking
    has_fcntl  = b'fcntl'  in binary_data
    has_select = (b'select' in binary_data
                  or b'poll\x00' in binary_data
                  or b'epoll'    in binary_data)
    o_nonblock_linux = b'\x00\x08\x00\x00'   # O_NONBLOCK=0x800 Linux LE int32
    o_nonblock_bsd   = b'\x04\x00\x00\x00'   # O_NONBLOCK=4    BSD   LE int32
    has_nonblock = (b'O_NONBLOCK' in binary_data
                    or o_nonblock_linux in binary_data
                    or o_nonblock_bsd   in binary_data)

    if has_fcntl and has_select and has_nonblock:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASYNC_SOCKET_MULTIPLEXING',
            'detail': (
                'Binary combines fcntl(F_SETFL, O_NONBLOCK) with select/poll/epoll — '
                'async socket multiplexing pattern used in high-speed port scanners and '
                'multi-target C2 beacons (AoE Ch. 0x400 port scanning). Single-threaded '
                'probing of thousands of hosts without blocking reduces per-host dwell time.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_exposed_debug_interface(host: str, port: int = 8888, timeout: float = 5.0) -> list:
    """Detect exposed debugging and exploitation surfaces on common debugger ports.

    Probes Python debugger (pdb/debugpy), Node.js inspector (CDP), Delve (Go),
    GDB Remote Serial Protocol stub, and Java JDWP endpoints. All debug interfaces
    grant unauthenticated remote code execution by design — exposure on any network
    interface is a critical severity finding.
    Returns List[dict] with keys: severity, title, detail, host, port.
    """
    import socket as _socket
    import json as _json

    findings = []

    def _tcp_connect(h: str, p: int, tmo: float):
        """Return connected TCP socket or None on failure."""
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.settimeout(tmo)
            s.connect((h, p))
            return s
        except (OSError, _socket.timeout):
            return None

    def _send_recv(s, data: bytes, read_size: int = 4096) -> bytes:
        """Send bytes, return response or b'' on error/timeout."""
        try:
            s.sendall(data)
            return s.recv(read_size)
        except (OSError, _socket.timeout):
            return b''

    # -- Python debugger (debugpy / pdb / pydevd): ports 5678, 8888 -------------------------
    # debugpy exposes a Debug Adapter Protocol (DAP) HTTP endpoint at /json.
    # pydevd (PyCharm remote debugger) sends an XML greeting on connect.
    for dbg_port in (5678, 8888):
        s = _tcp_connect(host, dbg_port, timeout)
        if s is None:
            continue
        try:
            req = b'GET /json HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n'
            resp = _send_recv(s, req, 8192)
            if resp:
                rl = resp.lower()
                if ((b'"type"' in rl and (b'python' in rl or b'debugpy' in rl))
                        or b'pydevd' in rl
                        or b'debugpy' in rl
                        or b'<xml' in rl
                        or b'<?xml' in rl
                        or (b'200 ok' in rl and b'json' in rl)):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'PYTHON_DEBUGGER_EXPOSED',
                        'detail': (
                            f'Python debugger (debugpy/pdb/pydevd) accessible at '
                            f'{host}:{dbg_port}. Debug Adapter Protocol allows unauthenticated '
                            'remote code execution: arbitrary Python eval, file system access, '
                            'environment variable extraction, and full process control. '
                            'No authentication on DAP or pydevd interfaces by default.'
                        ),
                        'host': host,
                        'port': dbg_port,
                    })
        finally:
            try:
                s.close()
            except OSError:
                pass

    # -- Node.js inspector (Chrome DevTools Protocol): port 9229 ----------------------------
    # GET /json/list returns CDP target list including webSocketDebuggerUrl.
    # Unauthenticated CDP = arbitrary JS eval in the Node.js process context.
    s = _tcp_connect(host, 9229, timeout)
    if s is not None:
        try:
            req = b'GET /json/list HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n'
            resp = _send_recv(s, req, 16384)
            if resp:
                rl = resp.lower()
                if (b'websocketdebuggerurl' in rl
                        or (b'200 ok' in rl and b'devtools' in rl)
                        or (b'200 ok' in rl and b'application/json' in rl)):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'NODE_INSPECTOR_EXPOSED',
                        'detail': (
                            f'Node.js inspector (Chrome DevTools Protocol) exposed at {host}:9229. '
                            'webSocketDebuggerUrl present in /json/list response. Unauthenticated '
                            'CDP access allows arbitrary JavaScript execution: child_process.exec() '
                            'for OS commands, file system read/write, environment variable dump, '
                            'and full process memory inspection.'
                        ),
                        'host': host,
                        'port': 9229,
                    })
        finally:
            try:
                s.close()
            except OSError:
                pass

    # -- Delve Go debugger: port 40000 -------------------------------------------------------
    # Delve exposes JSON-RPC 2.0; RPCServer.GetVersion is callable without authentication.
    # A successful result confirms an exploitable Delve instance.
    s = _tcp_connect(host, 40000, timeout)
    if s is not None:
        try:
            rpc_req = (_json.dumps({
                'method': 'RPCServer.GetVersion',
                'params': [{}],
                'id': 1,
            }) + '\n').encode()
            resp = _send_recv(s, rpc_req, 4096)
            if resp:
                resp_text = resp.decode('utf-8', errors='replace')
                if 'DelveVersion' in resp_text or ('"result"' in resp_text and '"error":null' in resp_text):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'DELVE_DEBUGGER_EXPOSED',
                        'detail': (
                            f'Delve (Go debugger) JSON-RPC server exposed at {host}:40000. '
                            'RPCServer.GetVersion returned a result without authentication. '
                            'Delve API allows: goroutine enumeration, breakpoint injection, '
                            'arbitrary Go expression evaluation (exec.Command), binary memory '
                            'read/write, and full process control including detach-and-kill.'
                        ),
                        'host': host,
                        'port': 40000,
                    })
        finally:
            try:
                s.close()
            except OSError:
                pass

    # -- GDB Remote Serial Protocol stub: ports 1234, 2345 ----------------------------------
    # RSP packet format: +$<data>#<checksum>
    # "?" query asks for the stop reason; valid response starts with "$S" or "$T"
    # Checksum of "?" is 0x3f
    for gdb_port in (1234, 2345):
        s = _tcp_connect(host, gdb_port, timeout)
        if s is None:
            continue
        try:
            rsp_query = b'+$?#3f'
            resp = _send_recv(s, rsp_query, 256)
            if resp:
                # Valid RSP stub echoes ack (+) then a stop-reason packet starting with $S/$T/$W/$X
                if (resp.startswith(b'+$S') or resp.startswith(b'+$T')
                        or resp.startswith(b'$S')  or resp.startswith(b'$T')
                        or (resp.startswith(b'+') and b'$' in resp)):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'GDB_REMOTE_STUB_EXPOSED',
                        'detail': (
                            f'GDB Remote Serial Protocol (RSP) stub responding at {host}:{gdb_port}. '
                            'RSP "?" query returned a stop-reason response without authentication. '
                            'Unauthenticated GDB RSP access enables: full memory read/write (m/M '
                            'packets), register inspection and modification (g/G packets), arbitrary '
                            'code execution via memory write and continue (c packet), and process '
                            'detach. Common on QEMU -gdb, JTAG bridges, and kernel debug stubs.'
                        ),
                        'host': host,
                        'port': gdb_port,
                    })
        finally:
            try:
                s.close()
            except OSError:
                pass

    # -- Java Debug Wire Protocol (JDWP): port 5005 -----------------------------------------
    # JDWP handshake: client sends 14-byte ASCII string "JDWP-Handshake";
    # server echoes the same 14 bytes on success. No authentication by default.
    s = _tcp_connect(host, 5005, timeout)
    if s is not None:
        try:
            jdwp_hs = b'JDWP-Handshake'
            resp = _send_recv(s, jdwp_hs, 64)
            if resp and b'JDWP-Handshake' in resp:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'JDWP_DEBUGGER_EXPOSED',
                    'detail': (
                        f'Java Debug Wire Protocol (JDWP) agent exposed at {host}:5005. '
                        'Handshake accepted without authentication. JDWP enables: arbitrary '
                        'Java bytecode injection via class redefinition, method invocation '
                        'in the JVM context, heap and thread enumeration, and full process '
                        'control. Classic exploitation: Runtime.exec() via JDWP method '
                        'invocation achieves OS command execution as the JVM process user.'
                    ),
                    'host': host,
                    'port': 5005,
                })
        finally:
            try:
                s.close()
            except OSError:
                pass

    return findings


def detect_heap_spray_artifacts() -> list:
    """
    Detect heap spray and memory corruption indicators on the local system.
    Synthesized from: Hacking: The Art of Exploitation - Overflows in Other Segments,
    Randomized Stack Space, and Nonexecutable Stack chapters.

    Key insight: heap spray reliability depends on predictable memory layouts.
    ASLR disabled (randomize_va_space=0) and mmap_min_addr=0 allow attackers
    to map executable memory at low/fixed addresses -- the same precondition
    that makes ret2libc and heap overflow exploitation deterministic.

    Checks:
    - /proc/sys/kernel/randomize_va_space: 0=CRITICAL ASLR_DISABLED; 1=HIGH ASLR_PARTIAL
    - /proc/sys/kernel/kptr_restrict: 0=HIGH KERNEL_PTRS_EXPOSED
    - /proc/sys/kernel/perf_event_paranoid: <0=HIGH PERF_EVENTS_UNRESTRICTED
    - /proc/sys/kernel/dmesg_restrict: 0=MEDIUM DMESG_UNRESTRICTED
    - /proc/sys/vm/mmap_min_addr: <65536=HIGH LOW_MMAP_MIN_ADDR
    - /proc/sys/kernel/suid_dumpable: 2=HIGH SUID_DUMPABLE_UNRESTRICTED
    - /proc/*/maps for large (>100MB) anonymous rwx mappings=CRITICAL LARGE_HEAP_SPRAY_REGION
    - /proc/*/maps for mappings at addresses below 0x10000=CRITICAL LOW_ADDRESS_MAPPING
    - /proc/*/status VmPeak > 90% total RAM=HIGH EXCESSIVE_MEMORY_USAGE

    Returns list of {severity, title, detail, host, port}.
    """
    import os

    findings = []

    def _read_sysctl(path):
        try:
            with open(path, 'r') as f:
                return f.read().strip()
        except Exception:
            return None

    # --- ASLR ---
    val = _read_sysctl('/proc/sys/kernel/randomize_va_space')
    if val is not None:
        try:
            aslr = int(val)
            if aslr == 0:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'ASLR_DISABLED',
                    'detail': (
                        'randomize_va_space=0: address space layout randomization fully disabled. '
                        'Heap, stack, and mmap regions sit at predictable addresses -- heap spray '
                        'and ret2libc attacks become deterministic. '
                        'Hacking AoE 2nd ed. ch.0x600 demonstrates that ASLR=0 restores full '
                        'stack-overflow exploitability on otherwise-modern kernels.'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
            elif aslr == 1:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ASLR_PARTIAL',
                    'detail': (
                        'randomize_va_space=1: only stack and VDSO randomized; heap and mmap '
                        'regions remain at fixed offsets. Heap-spray primitives can still target '
                        'predictable heap addresses. Recommend value 2 (full randomization).'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except ValueError:
            pass

    # --- kptr_restrict ---
    val = _read_sysctl('/proc/sys/kernel/kptr_restrict')
    if val is not None:
        try:
            if int(val) == 0:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'KERNEL_PTRS_EXPOSED',
                    'detail': (
                        'kptr_restrict=0: kernel symbol addresses readable by unprivileged users '
                        'via /proc/kallsyms and %pK format strings. Exposes ROP gadget addresses '
                        'needed to chain heap exploits into kernel code execution.'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except ValueError:
            pass

    # --- perf_event_paranoid ---
    val = _read_sysctl('/proc/sys/kernel/perf_event_paranoid')
    if val is not None:
        try:
            if int(val) < 0:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'PERF_EVENTS_UNRESTRICTED',
                    'detail': (
                        f'perf_event_paranoid={val}: unrestricted perf_event_open() for all '
                        'users. Allows side-channel attacks (cache-timing, branch prediction) '
                        'and assists heap-feng-shui by profiling allocator behavior without '
                        'privileges.'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except ValueError:
            pass

    # --- dmesg_restrict ---
    val = _read_sysctl('/proc/sys/kernel/dmesg_restrict')
    if val is not None:
        try:
            if int(val) == 0:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'DMESG_UNRESTRICTED',
                    'detail': (
                        'dmesg_restrict=0: kernel ring buffer readable by all users. '
                        'dmesg leaks physical addresses, slab pointer values, and crash '
                        'backtraces that reduce exploit development effort for heap primitives.'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except ValueError:
            pass

    # --- mmap_min_addr ---
    val = _read_sysctl('/proc/sys/vm/mmap_min_addr')
    if val is not None:
        try:
            if int(val) < 65536:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'LOW_MMAP_MIN_ADDR',
                    'detail': (
                        f'vm.mmap_min_addr={val}: userspace can mmap() below 65536. '
                        'NULL-dereference bugs become exploitable -- attacker maps page at '
                        'address 0 and places shellcode before triggering a kernel NULL ptr deref.'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except ValueError:
            pass

    # --- suid_dumpable ---
    val = _read_sysctl('/proc/sys/kernel/suid_dumpable')
    if val is not None:
        try:
            if int(val) == 2:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'SUID_DUMPABLE_UNRESTRICTED',
                    'detail': (
                        'suid_dumpable=2: core dumps enabled for SUID/privileged processes. '
                        'Core files may be written to attacker-controlled paths and contain '
                        'full process memory -- including heap spray payloads and live '
                        'credentials cached in privileged address spaces.'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except ValueError:
            pass

    # --- /proc/*/maps: large rwx anonymous regions and low-address mappings ---
    # Also /proc/*/status VmPeak > 90% of total RAM
    total_ram_kb = 0
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    parts = line.split()
                    if len(parts) >= 2:
                        total_ram_kb = int(parts[1])
                    break
    except Exception:
        pass

    _HUNDRED_MB = 100 * 1024 * 1024
    _LOW_ADDR_LIMIT = 0x10000

    try:
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            maps_path = '/proc/' + entry + '/maps'
            status_path = '/proc/' + entry + '/status'

            try:
                with open(maps_path, 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                        addr_range = parts[0]
                        perms = parts[1]
                        label = parts[5] if len(parts) > 5 else ''

                        try:
                            start_s, end_s = addr_range.split('-')
                            start = int(start_s, 16)
                            end = int(end_s, 16)
                        except ValueError:
                            continue

                        size = end - start
                        is_anon = label in ('', '[heap]', '[anon]')

                        if 'x' in perms and 'w' in perms and is_anon and size > _HUNDRED_MB:
                            findings.append({
                                'severity': 'CRITICAL',
                                'title': 'LARGE_HEAP_SPRAY_REGION',
                                'detail': (
                                    f'PID {entry}: large ({size // (1024 * 1024)}MB) anonymous '
                                    f'writable+executable mapping at '
                                    f'{hex(start)}-{hex(end)}. '
                                    'Executable anonymous mappings of this size are characteristic '
                                    'of heap spray -- shellcode NOP-sleds pre-positioned across a '
                                    'large address window to survive ASLR variance. '
                                    'Hacking AoE 2nd ed. ch.0x600: heap spray bypasses '
                                    'non-executable-stack protections when combined with JIT or '
                                    'anonymous mmap regions.'
                                ),
                                'host': 'localhost',
                                'port': 0,
                            })

                        if 0 < start < _LOW_ADDR_LIMIT:
                            findings.append({
                                'severity': 'CRITICAL',
                                'title': 'LOW_ADDRESS_MAPPING',
                                'detail': (
                                    f'PID {entry}: mapping at low address {hex(start)} '
                                    f'(below 0x{_LOW_ADDR_LIMIT:x}). '
                                    'Indicates mmap_min_addr bypass or privileged mapping '
                                    'near-NULL pages, enabling NULL-deref exploit primitives.'
                                ),
                                'host': 'localhost',
                                'port': 0,
                            })
            except (PermissionError, FileNotFoundError, OSError):
                pass

            if total_ram_kb > 0:
                try:
                    with open(status_path, 'r') as f:
                        for line in f:
                            if line.startswith('VmPeak:'):
                                parts = line.split()
                                if len(parts) >= 2:
                                    vm_peak_kb = int(parts[1])
                                    if vm_peak_kb > total_ram_kb * 0.9:
                                        findings.append({
                                            'severity': 'HIGH',
                                            'title': 'EXCESSIVE_MEMORY_USAGE',
                                            'detail': (
                                                f'PID {entry}: VmPeak={vm_peak_kb}kB exceeds '
                                                f'90% of total RAM ({total_ram_kb}kB). '
                                                'Abnormal peak virtual memory can indicate a '
                                                'heap spray in progress or prior spray attempt '
                                                'that exhausted address space.'
                                            ),
                                            'host': 'localhost',
                                            'port': 0,
                                        })
                                break
                except (PermissionError, FileNotFoundError, OSError):
                    pass
    except (PermissionError, FileNotFoundError, OSError):
        pass

    return findings


def detect_kernel_exploit_surface() -> list:
    """
    Detect kernel exploit attack surface conditions.
    Synthesized from: Hacking: The Art of Exploitation - Nonexecutable Stack (ret2libc),
    Randomized Stack Space, and Countermeasures chapters.

    Key insight: modern kernel exploits chain from userspace primitives to kernel
    code execution via ptrace, eBPF, io_uring, or namespace escape. Each enabled
    interface is a documented exploitation vector; their interaction multiplies
    attack surface beyond any single control.

    Checks:
    - /proc/sys/kernel/yama/ptrace_scope: 0=CRITICAL PTRACE_UNRESTRICTED
    - /proc/modules size-0 entries=HIGH SUSPICIOUS_KERNEL_MODULE
    - /proc/modules taint P/O flags=MEDIUM TAINTED_KERNEL
    - /proc/sys/kernel/unprivileged_bpf_disabled: 0=HIGH BPF_UNPRIVILEGED
    - /proc/sys/kernel/io_uring_disabled: 0 + io_uring in kallsyms=MEDIUM IO_URING_ENABLED
    - /proc/sys/user/max_user_namespaces: >0=HIGH USER_NAMESPACES_ENABLED
    - /proc/sys/vm/nr_hugepages: >1000=MEDIUM LARGE_HUGEPAGE_POOL
    - vsyscall in /proc/self/maps=INFO VSYSCALL_MAPPED
    - /proc/kallsyms readable=CRITICAL KALLSYMS_WORLD_READABLE

    Returns list of {severity, title, detail, host, port}.
    """
    import os

    findings = []

    def _read_sysctl(path):
        try:
            with open(path, 'r') as f:
                return f.read().strip()
        except Exception:
            return None

    # --- ptrace_scope ---
    val = _read_sysctl('/proc/sys/kernel/yama/ptrace_scope')
    if val is not None:
        try:
            if int(val) == 0:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'PTRACE_UNRESTRICTED',
                    'detail': (
                        'yama/ptrace_scope=0: any process can ptrace() any other process '
                        'owned by the same UID without restriction. Enables process injection, '
                        'credential extraction from live processes (sshd, sudo, gpg-agent), '
                        'and full memory read/write of peer processes. '
                        'Hacking AoE 2nd ed. ch.0x300 uses ptrace as the mechanism for '
                        'debugger-assisted memory write -- identical interface, zero authorization '
                        'at scope=0.'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except ValueError:
            pass

    # --- /proc/modules: size-0 and tainted entries ---
    try:
        with open('/proc/modules', 'r') as f:
            module_lines = f.readlines()

        zero_size_modules = []
        tainted_modules = []

        for line in module_lines:
            # Format: name size refcount used_by state address [taint]
            parts = line.split()
            if len(parts) < 6:
                continue
            mod_name = parts[0]
            try:
                mod_size = int(parts[1])
            except ValueError:
                mod_size = -1
            taint_field = parts[6] if len(parts) > 6 else ''

            if mod_size == 0:
                zero_size_modules.append(mod_name)

            # Taint flags appear in parentheses: (POE)
            if '(' in taint_field:
                flags = taint_field.strip('()')
                if 'P' in flags or 'O' in flags:
                    tainted_modules.append((mod_name, flags))

        if zero_size_modules:
            findings.append({
                'severity': 'HIGH',
                'title': 'SUSPICIOUS_KERNEL_MODULE',
                'detail': (
                    f'Kernel modules with size=0: {", ".join(zero_size_modules[:10])}. '
                    'Zero-size LKMs can indicate a rootkit that reports a false size to '
                    'evade accounting-based detection. Legitimate modules always have '
                    'non-zero code and data sections.'
                ),
                'host': 'localhost',
                'port': 0,
            })

        if tainted_modules:
            taint_summary = ', '.join(
                '{0}({1})'.format(n, f) for n, f in tainted_modules[:10]
            )
            findings.append({
                'severity': 'MEDIUM',
                'title': 'TAINTED_KERNEL',
                'detail': (
                    f'Kernel tainted by out-of-tree or proprietary modules: {taint_summary}. '
                    'P=proprietary/closed-source, O=out-of-tree. Non-mainline modules are '
                    'unaudited attack surface; proprietary modules cannot be inspected for '
                    'backdoors or hidden exploit primitives.'
                ),
                'host': 'localhost',
                'port': 0,
            })
    except (PermissionError, FileNotFoundError, OSError):
        pass

    # --- unprivileged BPF ---
    val = _read_sysctl('/proc/sys/kernel/unprivileged_bpf_disabled')
    if val is not None:
        try:
            if int(val) == 0:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'BPF_UNPRIVILEGED',
                    'detail': (
                        'unprivileged_bpf_disabled=0: unprivileged users can load eBPF programs. '
                        'eBPF verifier bypass bugs (CVE-2021-3490, CVE-2022-23222, '
                        'CVE-2023-2163) have enabled reliable kernel privilege escalation '
                        'from unprivileged context. Disable on non-container hosts.'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except ValueError:
            pass

    # --- io_uring ---
    uring_disabled_val = _read_sysctl('/proc/sys/kernel/io_uring_disabled')
    uring_in_kallsyms = False
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                if 'io_uring' in line:
                    uring_in_kallsyms = True
                    break
    except (PermissionError, FileNotFoundError, OSError):
        pass

    if uring_disabled_val is not None:
        try:
            if int(uring_disabled_val) == 0 and uring_in_kallsyms:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'IO_URING_ENABLED',
                    'detail': (
                        'io_uring_disabled=0 and io_uring present in kernel symbol table. '
                        'io_uring has been a recurring kernel exploit vector '
                        '(CVE-2022-29582, CVE-2023-2598, CVE-2024-0582). Its async I/O '
                        'model creates complex reference-counting and UAF conditions. '
                        'Disable with io_uring_disabled=1 if not required.'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except ValueError:
            pass

    # --- user namespaces ---
    val = _read_sysctl('/proc/sys/user/max_user_namespaces')
    if val is not None:
        try:
            if int(val) > 0:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'USER_NAMESPACES_ENABLED',
                    'detail': (
                        f'max_user_namespaces={val}: unprivileged user namespace creation '
                        'allowed. User namespaces grant unprivileged processes a mapped root '
                        'identity used to reach privileged kernel code paths (setuid mounts, '
                        'netfilter rules, BPF). Primary vector for container escape and '
                        'unprivileged privilege escalation chains.'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except ValueError:
            pass

    # --- huge pages ---
    val = _read_sysctl('/proc/sys/vm/nr_hugepages')
    if val is not None:
        try:
            if int(val) > 1000:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'LARGE_HUGEPAGE_POOL',
                    'detail': (
                        f'nr_hugepages={val}: large pool of pre-allocated huge pages. '
                        'Huge pages (2MB/1GB) reduce ASLR entropy for heap allocations -- '
                        'huge-page-backed heaps align to predictable 2MB boundaries, '
                        'narrowing the spray target window. Also provides contiguous large '
                        'physical memory regions that assist spray-based exploit primitives.'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except ValueError:
            pass

    # --- vsyscall region in /proc/self/maps ---
    try:
        with open('/proc/self/maps', 'r') as f:
            for line in f:
                if 'vsyscall' in line:
                    findings.append({
                        'severity': 'INFO',
                        'title': 'VSYSCALL_MAPPED',
                        'detail': (
                            f'vsyscall region in process address space: {line.strip()}. '
                            'The vsyscall page maps at a fixed address (0xffffffffff600000) '
                            'immune to ASLR, providing a stable ROP gadget anchor. '
                            'Used in ret2vsyscall chains to bypass address randomization. '
                            'Modern kernels support vsyscall=none to remove this fixed target.'
                        ),
                        'host': 'localhost',
                        'port': 0,
                    })
                    break
    except (PermissionError, FileNotFoundError, OSError):
        pass

    # --- /proc/kallsyms world-readable ---
    # Count readable symbols -- more symbols = more ROP gadgets available to attacker
    symbol_count = 0
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                if line.strip():
                    symbol_count += 1
                if symbol_count >= 10000:
                    break
    except (PermissionError, FileNotFoundError, OSError):
        pass

    if symbol_count > 0:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'KALLSYMS_WORLD_READABLE',
            'detail': (
                f'/proc/kallsyms readable -- sampled {symbol_count}+ symbols. '
                'Exposed kernel symbol addresses defeat KASLR: an attacker reads exact '
                'addresses of kernel functions and gadgets, converting a relative memory '
                'disclosure into a complete ROP chain construction primitive. '
                'More exported symbols = larger available ROP gadget set. '
                'Suppress with kptr_restrict=2 and perf_event_paranoid>=3.'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: syscall_trace.py <PID> [duration]")
        sys.exit(1)
    
    pid = int(sys.argv[1])
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    
    tracer = SyscallTracer(pid)
    
    print(f"[*] Tracing PID {pid} for {duration} seconds...")
    stats = tracer.trace_process(duration)
    
    print("\n" + tracer.report(stats))
