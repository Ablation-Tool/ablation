#!/usr/bin/env python3
"""
Process Enumeration Module
Synthesized from: Learning Linux Binary Analysis, Linux System Programming

Enumerate running processes, loaded modules, memory maps.
"""

import os
import re
import platform as _platform
import subprocess
from pathlib import Path

_IS_MACOS = _platform.system() == 'Darwin'
_IS_LINUX = _platform.system() == 'Linux'

class ProcessEnumerator:
    """Enumerate and analyze processes"""
    
    def __init__(self, pid=None):
        self.pid = pid or os.getpid()
        self.proc_path = Path(f"/proc/{self.pid}")
        
    def list_all_processes(self):
        """List all running processes"""
        if _IS_MACOS:
            return self._list_processes_macos()
        return self._list_processes_linux()

    def _list_processes_linux(self):
        procs = []
        for entry in Path("/proc").iterdir():
            if entry.is_dir() and entry.name.isdigit():
                pid = int(entry.name)
                try:
                    with open(entry / "comm") as f:
                        name = f.read().strip()
                    with open(entry / "cmdline") as f:
                        cmdline = f.read().replace('\x00', ' ').strip()
                    procs.append({'pid': pid, 'name': name, 'cmdline': cmdline or name})
                except:
                    pass
        return sorted(procs, key=lambda x: x['pid'])

    def _list_processes_macos(self):
        procs = []
        try:
            result = subprocess.run(
                ['ps', '-axo', 'pid,ppid,comm,args'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.split(None, 3)
                if len(parts) >= 3:
                    try:
                        procs.append({
                            'pid': int(parts[0]),
                            'name': parts[2].split('/')[-1],
                            'cmdline': parts[3] if len(parts) > 3 else parts[2]
                        })
                    except:
                        pass
        except:
            pass
        return sorted(procs, key=lambda x: x['pid'])
    
    def get_memory_maps(self):
        """Read process memory maps"""
        if _IS_MACOS:
            return self._get_memory_maps_macos()
        maps = []
        try:
            with open(self.proc_path / "maps") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        addr_range = parts[0]
                        perms = parts[1]
                        offset = parts[2]
                        dev = parts[3]
                        inode = parts[4]
                        pathname = ' '.join(parts[5:]) if len(parts) > 5 else ''
                        
                        start, end = addr_range.split('-')
                        maps.append({
                            'start': int(start, 16),
                            'end': int(end, 16),
                            'perms': perms,
                            'offset': int(offset, 16),
                            'pathname': pathname,
                            'readable': 'r' in perms,
                            'writable': 'w' in perms,
                            'executable': 'x' in perms
                        })
        except:
            pass
        
        return maps

    def _get_memory_maps_macos(self):
        maps = []
        try:
            result = subprocess.run(
                ['vmmap', '-wide', str(self.pid)],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return []
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 3 and '-' in parts[0] and parts[0][0:2] in ('0x', '') :
                    try:
                        addr_range = parts[0]
                        perms_str = parts[1] if len(parts) > 1 else '----'
                        pathname = parts[-1] if len(parts) > 4 else ''
                        addrs = addr_range.split('-')
                        if len(addrs) == 2:
                            maps.append({
                                'start': int(addrs[0], 16),
                                'end': int(addrs[1], 16),
                                'perms': perms_str,
                                'offset': 0,
                                'pathname': pathname,
                                'readable': 'r' in perms_str,
                                'writable': 'w' in perms_str,
                                'executable': 'x' in perms_str,
                            })
                    except:
                        pass
        except:
            pass
        return maps

    def get_loaded_modules(self):
        """Get loaded shared libraries"""
        maps = self.get_memory_maps()
        modules = {}
        
        for m in maps:
            if m['pathname'] and m['pathname'].endswith('.so') or '/lib' in m['pathname']:
                if m['pathname'] not in modules:
                    modules[m['pathname']] = {
                        'base': m['start'],
                        'path': m['pathname'],
                        'regions': []
                    }
                modules[m['pathname']]['regions'].append({
                    'start': m['start'],
                    'end': m['end'],
                    'perms': m['perms']
                })
        
        return list(modules.values())
    
    def find_executable_regions(self):
        """Find executable memory regions"""
        maps = self.get_memory_maps()
        return [m for m in maps if m['executable']]
    
    def find_writable_executable(self):
        """Find writable + executable regions (dangerous!)"""
        maps = self.get_memory_maps()
        return [m for m in maps if m['writable'] and m['executable']]
    
    def get_open_files(self):
        """List open file descriptors"""
        if _IS_MACOS:
            return self._get_open_files_macos()
        fds = []
        fd_path = self.proc_path / "fd"
        try:
            for fd in fd_path.iterdir():
                if fd.is_symlink():
                    target = os.readlink(str(fd))
                    fds.append({'fd': int(fd.name), 'target': target})
        except:
            pass
        return sorted(fds, key=lambda x: x['fd'])

    def _get_open_files_macos(self):
        fds = []
        try:
            result = subprocess.run(
                ['lsof', '-p', str(self.pid)],
                capture_output=True, text=True, timeout=5
            )
            for i, line in enumerate(result.stdout.strip().split('\n')):
                if i == 0:
                    continue
                parts = line.split(None, 8)
                if len(parts) >= 9:
                    try:
                        fds.append({'fd': parts[3], 'target': parts[8]})
                    except:
                        pass
        except:
            pass
        return fds
    
    def get_environment(self):
        """Read process environment variables"""
        if _IS_MACOS:
            return self._get_environment_macos()
        env = {}
        try:
            with open(self.proc_path / "environ", 'rb') as f:
                data = f.read().decode('utf-8', errors='ignore')
                for item in data.split('\x00'):
                    if '=' in item:
                        key, value = item.split('=', 1)
                        env[key] = value
        except:
            pass
        return env

    def _get_environment_macos(self):
        env = {}
        try:
            result = subprocess.run(
                ['ps', 'eww', '-p', str(self.pid)],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                env_part = lines[-1].strip()
                for token in env_part.split():
                    if '=' in token:
                        k, v = token.split('=', 1)
                        env[k] = v
        except:
            pass
        return env
    
    def report(self):
        """Generate full process report"""
        lines = []
        lines.append(f"Process: PID {self.pid}")

        if _IS_MACOS:
            try:
                result = subprocess.run(
                    ['ps', '-p', str(self.pid), '-o', 'pid,comm,args'],
                    capture_output=True, text=True, timeout=3
                )
                out_lines = result.stdout.strip().split('\n')
                if len(out_lines) >= 2:
                    parts = out_lines[1].split(None, 2)
                    if len(parts) >= 2:
                        lines.append(f"Name: {parts[1].split('/')[-1]}")
                    if len(parts) >= 3:
                        lines.append(f"Command: {parts[2]}")
            except:
                pass
        else:
            try:
                with open(self.proc_path / "comm") as f:
                    lines.append(f"Name: {f.read().strip()}")
                with open(self.proc_path / "cmdline") as f:
                    cmdline = f.read().replace('\x00', ' ').strip()
                    lines.append(f"Command: {cmdline}")
            except:
                pass
        
        # Memory maps
        maps = self.get_memory_maps()
        lines.append(f"\nMemory Regions: {len(maps)}")
        
        # Executable regions
        exec_regions = self.find_executable_regions()
        lines.append(f"Executable regions: {len(exec_regions)}")
        
        # Loaded modules
        modules = self.get_loaded_modules()
        lines.append(f"Loaded modules: {len(modules)}")
        if modules:
            lines.append("\nModules:")
            for mod in modules[:5]:  # First 5
                lines.append(f"  {mod['path']} @ {hex(mod['base'])}")
        
        # Dangerous regions
        wx = self.find_writable_executable()
        if wx:
            lines.append(f"\n⚠ Writable+Executable regions: {len(wx)}")
            for r in wx:
                lines.append(f"  {hex(r['start'])}-{hex(r['end'])} {r['perms']} {r['pathname']}")
        
        # Open files
        fds = self.get_open_files()
        lines.append(f"\nOpen file descriptors: {len(fds)}")
        
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Standalone forensics detection functions (Linux /proc-based)
# ---------------------------------------------------------------------------

import struct
import socket as _socket

_FINDING_HOST = "localhost"
_FINDING_PORT = 0

_WRITABLE_PATHS = ('/tmp', '/dev/shm', '/run/user', '/var/tmp')
_SUSPICIOUS_PROC_NAMES = {'python', 'python3', 'perl', 'ruby', 'sh', 'bash', 'nc', 'ncat', 'netcat'}


def _make_finding(severity: str, title: str, detail: str) -> dict:
    return {
        'severity': severity,
        'title': title,
        'detail': detail,
        'host': _FINDING_HOST,
        'port': _FINDING_PORT,
    }


def _not_linux_finding(func_name: str):
    return _make_finding('INFO', 'NOT_LINUX_SKIP', f'{func_name}: /proc not available on this platform')


def detect_hollow_process(pid: int) -> dict:
    """Detect process hollowing indicators for a given PID.

    Returns a finding dict: {severity, title, detail, host, port}.
    """
    if not os.path.isdir('/proc'):
        return _not_linux_finding('detect_hollow_process')

    proc_base = f'/proc/{pid}'

    # --- Check TracerPid (being ptrace-traced) ---
    tracer_pid = 0
    try:
        with open(f'{proc_base}/status') as f:
            for line in f:
                if line.startswith('TracerPid:'):
                    tracer_pid = int(line.split(':', 1)[1].strip())
                    break
    except OSError:
        pass

    if tracer_pid != 0:
        return _make_finding(
            'LOW',
            'PROCESS_BEING_TRACED',
            f'PID {pid} has TracerPid={tracer_pid} — process is attached to by a debugger/ptrace',
        )

    # --- Check exe vs cmdline mismatch ---
    exe_path = ''
    cmdline_exe = ''
    try:
        exe_path = os.readlink(f'{proc_base}/exe')
    except OSError:
        pass
    try:
        with open(f'{proc_base}/cmdline', 'rb') as f:
            raw = f.read()
        args = raw.split(b'\x00')
        if args:
            cmdline_exe = args[0].decode('utf-8', errors='replace')
    except OSError:
        pass

    if exe_path and cmdline_exe and exe_path != cmdline_exe:
        # Resolve cmdline_exe if relative
        try:
            resolved = os.path.realpath(cmdline_exe)
        except Exception:
            resolved = cmdline_exe
        if resolved != exe_path and not cmdline_exe.startswith('-'):
            return _make_finding(
                'MEDIUM',
                'EXECUTABLE_PATH_MISMATCH',
                f'PID {pid}: /proc/exe={exe_path!r} != cmdline[0]={cmdline_exe!r} — possible process replacement',
            )

    # --- Check maps for rwx or suspicious .text region ---
    try:
        with open(f'{proc_base}/maps') as f:
            map_lines = f.readlines()
    except OSError:
        map_lines = []

    prev_end = None
    prev_perms = ''
    prev_path = ''
    for line in map_lines:
        parts = line.strip().split()
        if len(parts) < 5:
            continue
        addr_range = parts[0]
        perms = parts[1]
        pathname = ' '.join(parts[5:]) if len(parts) > 5 else ''

        try:
            start_s, end_s = addr_range.split('-')
            start = int(start_s, 16)
            end = int(end_s, 16)
        except ValueError:
            prev_end = None
            continue

        # rwx page = suspicious
        if 'r' in perms and 'w' in perms and 'x' in perms:
            return _make_finding(
                'HIGH',
                'PROCESS_HOLLOW_SUSPECT',
                f'PID {pid}: RWX mapping at {addr_range} path={pathname!r} — '
                'simultaneous write+execute permissions suggest shellcode or hollowing',
            )

        # Gap after r-xp: could indicate hollowed .text replaced by anonymous mapping
        if prev_end is not None and prev_perms == 'r-xp' and start > prev_end and not pathname and not prev_path.startswith('['):
            return _make_finding(
                'HIGH',
                'PROCESS_HOLLOW_SUSPECT',
                f'PID {pid}: gap after r-xp region ending at {hex(prev_end)}; '
                f'next region starts at {hex(start)} (anonymous) — entry-point displacement consistent with hollowing',
            )

        prev_end = end
        prev_perms = perms
        prev_path = pathname

    return _make_finding(
        'INFO',
        'HOLLOW_CHECK_CLEAN',
        f'PID {pid}: no process hollowing indicators detected',
    )


def scan_dll_hijacking_candidates(proc_path: str = "/proc") -> list:
    """Scan all processes for DLL/shared-object hijacking indicators.

    Returns list of finding dicts.
    """
    if not os.path.isdir('/proc'):
        return [_not_linux_finding('scan_dll_hijacking_candidates')]

    findings = []

    try:
        pid_dirs = [
            e for e in os.scandir(proc_path)
            if e.is_dir() and e.name.isdigit()
        ]
    except OSError:
        return [_make_finding('INFO', 'PROC_SCAN_ERROR', f'Cannot scandir {proc_path}')]

    for entry in pid_dirs:
        pid = entry.name
        proc_base = entry.path

        # --- LD_PRELOAD check ---
        try:
            with open(f'{proc_base}/environ', 'rb') as f:
                raw_env = f.read().decode('utf-8', errors='replace')
            env_vars = {}
            for item in raw_env.split('\x00'):
                if '=' in item:
                    k, v = item.split('=', 1)
                    env_vars[k] = v

            if 'LD_PRELOAD' in env_vars:
                findings.append(_make_finding(
                    'CRITICAL',
                    'LD_PRELOAD_INJECTION',
                    f'PID {pid}: LD_PRELOAD={env_vars["LD_PRELOAD"]!r} — shared library preloaded; '
                    'common rootkit/hooking technique',
                ))

            if 'LD_LIBRARY_PATH' in env_vars:
                llp = env_vars['LD_LIBRARY_PATH']
                standard = {'/lib', '/lib64', '/usr/lib', '/usr/lib64', '/usr/local/lib'}
                paths = [p for p in llp.split(':') if p]
                non_standard = [p for p in paths if not any(p.startswith(s) for s in standard)]
                if non_standard:
                    findings.append(_make_finding(
                        'HIGH',
                        'LD_LIBRARY_PATH_MANIPULATION',
                        f'PID {pid}: LD_LIBRARY_PATH contains non-standard dirs: {non_standard}',
                    ))
        except OSError:
            pass

        # --- /proc/{pid}/maps world-writable path check ---
        try:
            with open(f'{proc_base}/maps') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 6:
                        continue
                    pathname = ' '.join(parts[5:])
                    if not pathname or pathname.startswith('['):
                        continue
                    if any(pathname.startswith(wp) for wp in _WRITABLE_PATHS):
                        findings.append(_make_finding(
                            'HIGH',
                            'DLL_HIJACK_WRITABLE_PATH',
                            f'PID {pid}: mapped library from writable path: {pathname!r}',
                        ))
        except OSError:
            pass

    return findings


def _hex_to_ip(hex_str: str) -> str:
    """Convert little-endian hex address from /proc/net/tcp to dotted-decimal."""
    try:
        packed = bytes.fromhex(hex_str)[::-1]  # little-endian
        return _socket.inet_ntop(_socket.AF_INET, packed)
    except Exception:
        return hex_str


def _hex_to_ip6(hex_str: str) -> str:
    """Convert /proc/net/tcp6 address (4 little-endian 32-bit words) to IPv6."""
    try:
        raw = bytes.fromhex(hex_str)
        # Each 4-byte word is little-endian; reverse each word
        result = b''
        for i in range(0, 16, 4):
            result += raw[i:i+4][::-1]
        return _socket.inet_ntop(_socket.AF_INET6, result)
    except Exception:
        return hex_str


def _inode_to_pid_name() -> dict:
    """Build mapping: socket inode -> (pid, process_name)."""
    inode_map = {}
    try:
        for entry in os.scandir('/proc'):
            if not entry.is_dir() or not entry.name.isdigit():
                continue
            pid = entry.name
            fd_dir = f'/proc/{pid}/fd'
            try:
                comm = ''
                try:
                    with open(f'/proc/{pid}/comm') as f:
                        comm = f.read().strip()
                except OSError:
                    pass
                for fd_entry in os.scandir(fd_dir):
                    try:
                        target = os.readlink(fd_entry.path)
                        if target.startswith('socket:['):
                            inode = target[8:-1]
                            inode_map[inode] = (pid, comm)
                    except OSError:
                        pass
            except OSError:
                pass
    except OSError:
        pass
    return inode_map


_RFC1918_RANGES = [
    (0x0A000000, 0xFF000000),   # 10.0.0.0/8
    (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
    (0x7F000000, 0xFF000000),   # 127.0.0.0/8  (loopback)
]


def _is_private_or_loopback(ip_str: str) -> bool:
    try:
        packed = _socket.inet_aton(ip_str)
        addr = struct.unpack('!I', packed)[0]
        for net, mask in _RFC1918_RANGES:
            if addr & mask == net:
                return True
    except OSError:
        pass
    return False


_COMMON_PORTS = {22, 80, 443, 8080, 8443}
_LISTEN_STATE = '0A'
_ESTABLISHED_STATE = '01'


def detect_suspicious_network_sockets(timeout: float = 3.0) -> list:
    """Detect suspicious network socket patterns via /proc/net/tcp and /proc/net/tcp6.

    Returns list of finding dicts.
    """
    if not os.path.isdir('/proc'):
        return [_not_linux_finding('detect_suspicious_network_sockets')]

    findings = []
    inode_map = _inode_to_pid_name()

    for tcp_file in ('/proc/net/tcp', '/proc/net/tcp6'):
        is_v6 = tcp_file.endswith('6')
        try:
            with open(tcp_file) as f:
                lines = f.readlines()[1:]  # skip header
        except OSError:
            continue

        for line in lines:
            parts = line.strip().split()
            if len(parts) < 12:
                continue

            local_addr_hex, local_port_hex = parts[1].split(':')
            remote_addr_hex, remote_port_hex = parts[2].split(':')
            state = parts[3]
            inode = parts[9]

            try:
                local_port = int(local_port_hex, 16)
                remote_port = int(remote_port_hex, 16)
            except ValueError:
                continue

            pid_name = inode_map.get(inode, ('?', '?'))
            pid, pname = pid_name

            if is_v6:
                local_ip = _hex_to_ip6(local_addr_hex)
                remote_ip = _hex_to_ip6(remote_addr_hex)
            else:
                local_ip = _hex_to_ip(local_addr_hex)
                remote_ip = _hex_to_ip(remote_addr_hex)

            # Unusual LISTEN on 0.0.0.0
            if state == _LISTEN_STATE and local_port not in _COMMON_PORTS:
                bind_all = (local_ip in ('0.0.0.0', '::'))
                if bind_all:
                    findings.append(_make_finding(
                        'HIGH',
                        'UNUSUAL_LISTEN_PORT',
                        f'PID {pid} ({pname}): listening on 0.0.0.0:{local_port} — '
                        'not a standard service port; possible backdoor listener',
                    ))

            # ESTABLISHED from suspicious process to non-private address
            if state == _ESTABLISHED_STATE:
                proc_basename = pname.lower().rstrip('0123456789')
                if proc_basename in _SUSPICIOUS_PROC_NAMES:
                    if not is_v6 and not _is_private_or_loopback(remote_ip):
                        findings.append(_make_finding(
                            'HIGH',
                            'SUSPICIOUS_SHELL_NETWORK_CONN',
                            f'PID {pid} ({pname}): established outbound connection to {remote_ip}:{remote_port} — '
                            'interpreter/shell process with external network connection',
                        ))

    return findings


def detect_cron_persistence(paths: list = None) -> list:
    """Detect persistence mechanisms via cron/scheduled task files.

    Returns list of finding dicts.
    """
    if not os.path.isdir('/proc') and not os.path.isdir('/etc'):
        return [_not_linux_finding('detect_cron_persistence')]

    if paths is None:
        paths = [
            '/etc/crontab',
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly',
            '/var/spool/cron/crontabs',
        ]

    _REVERSE_SHELL_RE = re.compile(
        r'(bash\s+-i|/dev/tcp|nc\s+-e|ncat\s+-e|python\s+-c|perl\s+-e|ruby\s+-e|'
        r'curl\s+.*\|\s*bash|wget\s+.*\|\s*bash|mkfifo|socat)',
        re.IGNORECASE,
    )
    _WRITABLE_PATH_RE = re.compile(
        r'(/tmp/|/dev/shm/|/run/user/)',
        re.IGNORECASE,
    )

    findings = []
    files_checked = []

    def _collect_files(path_str):
        p = Path(path_str)
        if not p.exists():
            return
        if p.is_file():
            files_checked.append(p)
        elif p.is_dir():
            try:
                for child in p.iterdir():
                    if child.is_file():
                        files_checked.append(child)
            except PermissionError:
                pass

    for path in paths:
        _collect_files(path)

    for cron_file in files_checked:
        # World-writable check
        try:
            stat_res = os.stat(str(cron_file))
            if stat_res.st_mode & 0o002:
                findings.append(_make_finding(
                    'CRITICAL',
                    'WORLD_WRITABLE_CRON',
                    f'{cron_file}: world-writable cron file — attacker can append arbitrary jobs',
                ))
        except OSError:
            pass

        # Content checks
        try:
            with open(str(cron_file), errors='replace') as f:
                for lineno, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith('#'):
                        continue

                    if _REVERSE_SHELL_RE.search(stripped):
                        findings.append(_make_finding(
                            'CRITICAL',
                            'CRON_REVERSE_SHELL_PATTERN',
                            f'{cron_file}:{lineno}: reverse-shell pattern detected: {stripped[:120]!r}',
                        ))
                    elif _WRITABLE_PATH_RE.search(stripped):
                        findings.append(_make_finding(
                            'HIGH',
                            'CRON_CALLS_WRITABLE_PATH',
                            f'{cron_file}:{lineno}: cron entry references writable path: {stripped[:120]!r}',
                        ))
        except OSError:
            pass

    return findings


def enumerate_volatile_forensics(output_dir: str = None) -> dict:
    """Full volatile forensics snapshot — calls all detection functions and aggregates results.

    Returns dict with keys:
        hollow_suspects, dll_hijacks, suspicious_sockets, cron_persistence, process_list
    """
    if not os.path.isdir('/proc'):
        return {
            'hollow_suspects': [_not_linux_finding('enumerate_volatile_forensics')],
            'dll_hijacks': [],
            'suspicious_sockets': [],
            'cron_persistence': [],
            'process_list': [],
        }

    # Build process list with parent PID and fd count
    process_list = []
    try:
        for entry in os.scandir('/proc'):
            if not entry.is_dir() or not entry.name.isdigit():
                continue
            pid = int(entry.name)
            proc_base = entry.path
            info = {'pid': pid, 'name': '', 'cmdline': '', 'ppid': 0, 'fd_count': 0}

            try:
                with open(f'{proc_base}/comm') as f:
                    info['name'] = f.read().strip()
            except OSError:
                pass

            try:
                with open(f'{proc_base}/cmdline', 'rb') as f:
                    raw = f.read().decode('utf-8', errors='replace')
                info['cmdline'] = raw.replace('\x00', ' ').strip()
            except OSError:
                pass

            try:
                with open(f'{proc_base}/status') as f:
                    for line in f:
                        if line.startswith('PPid:'):
                            info['ppid'] = int(line.split(':', 1)[1].strip())
                            break
            except OSError:
                pass

            try:
                fd_dir = f'{proc_base}/fd'
                info['fd_count'] = sum(1 for _ in os.scandir(fd_dir))
            except OSError:
                pass

            process_list.append(info)
    except OSError:
        pass

    process_list.sort(key=lambda x: x['pid'])

    # Hollow check on every PID
    hollow_suspects = []
    for proc in process_list:
        result = detect_hollow_process(proc['pid'])
        if result.get('severity') not in ('INFO',):
            hollow_suspects.append(result)

    dll_hijacks = scan_dll_hijacking_candidates()
    suspicious_sockets = detect_suspicious_network_sockets()
    cron_persistence = detect_cron_persistence()

    aggregated = {
        'hollow_suspects': hollow_suspects,
        'dll_hijacks': dll_hijacks,
        'suspicious_sockets': suspicious_sockets,
        'cron_persistence': cron_persistence,
        'process_list': process_list,
    }

    if output_dir:
        import json
        out = Path(output_dir)
        try:
            out.mkdir(parents=True, exist_ok=True)
            with open(out / 'volatile_forensics.json', 'w') as f:
                json.dump(aggregated, f, indent=2)
        except OSError:
            pass

    return aggregated


def detect_timestomping_indicators(scan_path="/tmp") -> list:
    """Detect file timestamp anomalies indicative of timestomping."""
    findings = []

    try:
        for root, dirs, files in os.walk(scan_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    st = os.stat(fpath)
                    mtime = st.st_mtime
                    ctime = st.st_ctime
                    atime = st.st_atime

                    # mtime backdated: ctime (inode change) is newer than mtime
                    if ctime > mtime + 1.0:
                        findings.append({
                            'severity': 'MEDIUM',
                            'title': 'MTIME_PRECEDES_CTIME — possible timestomping',
                            'detail': f'{fpath}: mtime={mtime:.0f} ctime={ctime:.0f} delta={ctime - mtime:.1f}s',
                            'host': 'localhost',
                            'port': 0,
                        })

                    # atime and mtime identical to the second — suspicious precision
                    if abs(atime - mtime) < 1.0 and atime != 0:
                        import math
                        if math.floor(atime) == math.floor(mtime):
                            findings.append({
                                'severity': 'MEDIUM',
                                'title': 'IDENTICAL_ATIME_MTIME',
                                'detail': f'{fpath}: atime={atime:.3f} mtime={mtime:.3f}',
                                'host': 'localhost',
                                'port': 0,
                            })

                    # Zeroed timestamps: epoch 0 (1970) or year 2000 boundary
                    import datetime
                    for ts_name, ts_val in (('mtime', mtime), ('atime', atime)):
                        if ts_val == 0:
                            findings.append({
                                'severity': 'HIGH',
                                'title': 'ZEROED_TIMESTAMP — timestomping artifact',
                                'detail': f'{fpath}: {ts_name}=0 (epoch)',
                                'host': 'localhost',
                                'port': 0,
                            })
                        else:
                            try:
                                year = datetime.datetime.utcfromtimestamp(ts_val).year
                                if year in (1970, 2000):
                                    findings.append({
                                        'severity': 'HIGH',
                                        'title': 'ZEROED_TIMESTAMP — timestomping artifact',
                                        'detail': f'{fpath}: {ts_name} year={year} ({ts_val:.0f})',
                                        'host': 'localhost',
                                        'port': 0,
                                    })
                            except (OSError, ValueError, OverflowError):
                                pass

                except OSError:
                    continue
    except OSError:
        pass

    return findings


def detect_log_tampering_indicators() -> list:
    """Detect log clearing and tampering artifacts."""
    findings = []

    # Standard log files: check for zero-byte truncation
    log_files = [
        '/var/log/auth.log',
        '/var/log/syslog',
        '/var/log/messages',
    ]
    for lf in log_files:
        try:
            st = os.stat(lf)
            if st.st_size == 0:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'LOG_FILE_TRUNCATED',
                    'detail': f'{lf}: size=0 (truncated or cleared)',
                    'host': 'localhost',
                    'port': 0,
                })
        except OSError:
            pass

    # /proc/kmsg: readable but empty suggests kernel log cleared
    try:
        import select
        fd = os.open('/proc/kmsg', os.O_RDONLY | os.O_NONBLOCK)
        try:
            r, _, _ = select.select([fd], [], [], 0)
            if not r:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'KERNEL_LOG_EMPTY',
                    'detail': '/proc/kmsg readable but no pending entries despite system activity',
                    'host': 'localhost',
                    'port': 0,
                })
        finally:
            os.close(fd)
    except OSError:
        pass

    # wtmp: record size must be a multiple of 384 bytes (struct utmp = 384 on Linux x86_64)
    UTMP_RECORD_SIZE = 384
    for wtmp_path in ('/var/log/wtmp', '/var/log/btmp'):
        try:
            size = os.path.getsize(wtmp_path)
            if size > 0 and (size % UTMP_RECORD_SIZE) != 0:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'WTMP_PARTIAL_RECORD — log manipulation',
                    'detail': (
                        f'{wtmp_path}: size={size} not divisible by {UTMP_RECORD_SIZE} '
                        f'(remainder={size % UTMP_RECORD_SIZE}) — partial record indicates tampering'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except OSError:
            pass

    # systemd journal: both runtime and persistent journals absent
    run_journal = '/run/log/journal'
    var_journal = '/var/log/journal'
    run_empty = not os.path.isdir(run_journal) or not any(True for _ in os.scandir(run_journal)) if os.path.isdir(run_journal) else True
    var_missing = not os.path.isdir(var_journal)
    if run_empty and var_missing:
        findings.append({
            'severity': 'HIGH',
            'title': 'JOURNAL_MISSING — possible clearing',
            'detail': f'{run_journal} empty/absent and {var_journal} absent — systemd journal may have been cleared',
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_memory_artifact_indicators() -> list:
    """Detect in-memory malware artifacts via /proc filesystem."""
    findings = []

    known_lib_prefixes = ('/lib', '/usr/lib', '/usr/local/lib', '/usr/lib64', '/lib64')
    excessive_anon_threshold = 50

    try:
        proc_root = '/proc'
        for entry in os.scandir(proc_root):
            if not entry.name.isdigit():
                continue
            pid = entry.name
            maps_path = f'/proc/{pid}/maps'
            exe_path = f'/proc/{pid}/exe'

            # Check for deleted binary (fileless malware)
            try:
                exe_target = os.readlink(exe_path)
                if '(deleted)' in exe_target:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'PROCESS_BINARY_DELETED — fileless malware',
                        'detail': f'PID {pid}: exe -> {exe_target}',
                        'host': 'localhost',
                        'port': 0,
                    })
            except OSError:
                pass

            try:
                with open(maps_path, 'r', errors='replace') as f:
                    lines = f.readlines()
            except OSError:
                continue

            anon_rwx_count = 0
            anon_mmap_count = 0

            for line in lines:
                parts = line.split()
                if len(parts) < 5:
                    continue
                perms = parts[1] if len(parts) > 1 else ''
                pathname = parts[5] if len(parts) > 5 else ''

                is_anonymous = not pathname or pathname in ('[heap]', '[stack]', '[vvar]', '[vdso]', '[vsyscall]')

                # Anonymous RWX mapping: shellcode injection
                if is_anonymous and 'r' in perms and 'w' in perms and 'x' in perms:
                    anon_rwx_count += 1

                # Count anonymous mmaps for heap-spray detection
                if not pathname:
                    anon_mmap_count += 1

                # Foreign library: mapped file not under known lib paths
                if pathname and pathname.startswith('/') and '(deleted)' not in pathname:
                    if pathname.endswith('.so') or '.so.' in pathname:
                        if not any(pathname.startswith(p) for p in known_lib_prefixes):
                            findings.append({
                                'severity': 'HIGH',
                                'title': 'FOREIGN_LIBRARY_LOADED',
                                'detail': f'PID {pid}: {pathname} (perms={perms})',
                                'host': 'localhost',
                                'port': 0,
                            })

            if anon_rwx_count > 0:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'ANONYMOUS_RWX_MAPPING — shellcode injection',
                    'detail': f'PID {pid}: {anon_rwx_count} anonymous rwx mapping(s) in /proc/{pid}/maps',
                    'host': 'localhost',
                    'port': 0,
                })

            if anon_mmap_count > excessive_anon_threshold:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'EXCESSIVE_ANON_MMAPS — heap spraying',
                    'detail': f'PID {pid}: {anon_mmap_count} anonymous mmap regions (threshold={excessive_anon_threshold})',
                    'host': 'localhost',
                    'port': 0,
                })

    except OSError:
        pass

    return findings


def detect_persistence_artifacts() -> list:
    """Detect Linux persistence mechanisms and backdoor artifacts."""
    findings = []

    # Shell profile backdoor: base64 decode+eval patterns
    import re
    import pathlib
    b64_eval_pattern = re.compile(
        r'(base64\s*[-]d|base64_decode|echo\s+[A-Za-z0-9+/=]{20,}\s*\|.*eval|eval\s*.*base64)',
        re.IGNORECASE,
    )
    shell_profiles = [
        pathlib.Path.home() / '.bashrc',
        pathlib.Path.home() / '.profile',
        pathlib.Path.home() / '.bash_profile',
        pathlib.Path('/root/.bashrc'),
        pathlib.Path('/root/.profile'),
        pathlib.Path('/root/.bash_profile'),
    ]
    seen_profiles = set()
    for profile in shell_profiles:
        try:
            resolved = str(profile.resolve())
            if resolved in seen_profiles:
                continue
            seen_profiles.add(resolved)
            content = profile.read_text(errors='replace')
            if b64_eval_pattern.search(content):
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'SHELL_PROFILE_BACKDOOR',
                    'detail': f'{profile}: base64 decode+eval pattern detected',
                    'host': 'localhost',
                    'port': 0,
                })
        except OSError:
            pass

    # ld.so.preload: non-empty = global hooking
    preload_path = '/etc/ld.so.preload'
    try:
        size = os.path.getsize(preload_path)
        if size > 0:
            try:
                content = open(preload_path, 'r', errors='replace').read().strip()
            except OSError:
                content = '<unreadable>'
            findings.append({
                'severity': 'CRITICAL',
                'title': 'LD_SO_PRELOAD_ACTIVE — global hooking',
                'detail': f'{preload_path}: {content[:200]}',
                'host': 'localhost',
                'port': 0,
            })
    except OSError:
        pass

    # ld.so.conf.d: world-writable .conf files
    ld_conf_d = '/etc/ld.so.conf.d'
    try:
        for entry in os.scandir(ld_conf_d):
            if entry.name.endswith('.conf'):
                try:
                    mode = entry.stat().st_mode
                    if mode & 0o002:  # world-writable
                        findings.append({
                            'severity': 'HIGH',
                            'title': 'LD_CONF_D_WRITABLE',
                            'detail': f'{entry.path}: mode={oct(mode)} (world-writable)',
                            'host': 'localhost',
                            'port': 0,
                        })
                except OSError:
                    pass
    except OSError:
        pass

    # kernel module loading enabled + unknown modules
    modules_disabled_path = '/proc/sys/kernel/modules_disabled'
    modules_path = '/proc/modules'
    known_module_prefixes = (
        'nf_', 'ip_', 'xt_', 'ipt_', 'ip6', 'bridge', 'stp', 'llc',
        'vmw_', 'vmware', 'vboxsf', 'vboxguest', 'vboxvideo',
        'ext4', 'ext3', 'ext2', 'xfs', 'btrfs', 'fat', 'vfat', 'ntfs',
        'ahci', 'libata', 'scsi', 'sd_mod', 'sr_mod', 'cdrom',
        'e1000', 'virtio', 'drm', 'video', 'i915', 'radeon', 'nouveau',
        'bluetooth', 'rfkill', 'cfg80211', 'mac80211',
        'pcspkr', 'serio', 'i2c', 'acpi', 'power', 'thermal',
        'crypto', 'aes', 'sha', 'crc', 'lzo', 'deflate',
        'loop', 'dm_', 'raid', 'md_', 'linear',
        'fuse', 'overlay', 'aufs', 'squashfs', 'isofs', 'udf',
        'tun', 'tap', 'dummy', 'bonding', 'vlan', '8021',
        'usb', 'hid', 'usbhid', 'uhci', 'ehci', 'xhci', 'ohci',
        'psmouse', 'mousedev', 'evdev', 'input',
        'snd_', 'sound', 'ac97', 'hda_',
    )
    try:
        disabled_val = open(modules_disabled_path).read().strip()
        if disabled_val == '0':
            # Module loading enabled; enumerate loaded modules for unknowns
            unknown_modules = []
            try:
                with open(modules_path) as f:
                    for line in f:
                        mod_name = line.split()[0] if line.split() else ''
                        if mod_name and not any(mod_name.startswith(p) for p in known_module_prefixes):
                            unknown_modules.append(mod_name)
            except OSError:
                pass
            findings.append({
                'severity': 'MEDIUM',
                'title': 'MODULE_LOAD_ENABLED',
                'detail': (
                    f'modules_disabled=0; potentially unknown modules: '
                    f'{", ".join(unknown_modules[:10]) if unknown_modules else "none flagged"}'
                ),
                'host': 'localhost',
                'port': 0,
            })
    except OSError:
        pass

    # PAM modules modified in last 48 hours
    pam_d = '/etc/pam.d'
    now = time.time()
    pam_window = 48 * 3600
    try:
        for entry in os.scandir(pam_d):
            try:
                mtime = entry.stat().st_mtime
                if (now - mtime) < pam_window:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'PAM_MODULE_RECENTLY_MODIFIED',
                        'detail': (
                            f'{entry.path}: mtime={mtime:.0f} '
                            f'({(now - mtime) / 3600:.1f}h ago)'
                        ),
                        'host': 'localhost',
                        'port': 0,
                    })
            except OSError:
                pass
    except OSError:
        pass

    return findings


# ---------------------------------------------------------------------------
# ELF binary analysis functions (stdlib only: struct, os, re)
# Synthesized from: Practical Binary Analysis ch01 (ELF anatomy) + ch05
# (binary instrumentation, DBI/ptrace tracing)
# ---------------------------------------------------------------------------

import struct as _struct


def analyze_elf_suspicious_sections(binary_data: bytes) -> list:
    """Parse ELF binary and flag suspicious sections/segments.

    Checks:
    - RWX section (SHF_EXECINSTR|SHF_WRITE simultaneously) -> CRITICAL
    - High-entropy non-standard section name -> HIGH (packed/encrypted)
    - LOAD segment with p_flags=7 (PF_X|PF_W|PF_R) -> CRITICAL
    - SHT_NOTE section at unexpected index -> MEDIUM

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings = []
    if len(binary_data) < 16:
        return findings

    # Verify ELF magic
    if binary_data[:4] != b'\x7fELF':
        return findings

    ei_class = binary_data[4]  # 1=32-bit, 2=64-bit
    ei_data  = binary_data[5]  # 1=LE, 2=BE
    endian   = '<' if ei_data != 2 else '>'

    _KNOWN_SECTIONS = {
        '.text', '.data', '.bss', '.rodata', '.plt', '.got', '.got.plt',
        '.dynsym', '.symtab', '.strtab', '.shstrtab', '.dynstr',
        '.dynamic', '.interp', '.note', '.note.ABI-tag',
        '.note.gnu.build-id', '.rela.dyn', '.rela.plt', '.rel.dyn',
        '.rel.plt', '.eh_frame', '.eh_frame_hdr', '.init', '.fini',
        '.init_array', '.fini_array', '.debug_info', '.debug_abbrev',
        '.debug_line', '.comment',
    }

    SHF_WRITE     = 0x1
    SHF_EXECINSTR = 0x4
    SHT_NOTE      = 7
    SHT_NULL      = 0

    try:
        if ei_class == 1:
            # 32-bit ELF header
            hdr_fmt  = endian + 'HHIIIIIHHHHHH'
            hdr_size = _struct.calcsize(hdr_fmt)
            if len(binary_data) < 16 + hdr_size:
                return findings
            hdr = _struct.unpack_from(hdr_fmt, binary_data, 16)
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = hdr
            ph_fmt = endian + 'IIIIIIII'
            sh_fmt = endian + 'IIIIIIIIII'
        else:
            # 64-bit ELF header
            hdr_fmt  = endian + 'HHIQQQIHHHHHH'
            hdr_size = _struct.calcsize(hdr_fmt)
            if len(binary_data) < 16 + hdr_size:
                return findings
            hdr = _struct.unpack_from(hdr_fmt, binary_data, 16)
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = hdr
            ph_fmt = endian + 'IIQQQQQQ'
            sh_fmt = endian + 'IIQQQQIIQQ'
    except _struct.error:
        return findings

    # ---- Section header analysis ----
    sh_fmt_size = _struct.calcsize(sh_fmt)

    # Parse section string table for names
    shstrtab_data = b''
    if (e_shstrndx != 0xffff and e_shstrndx < e_shnum and
            e_shoff > 0 and e_shentsize >= sh_fmt_size):
        sh_str_offset = e_shoff + e_shstrndx * e_shentsize
        try:
            if ei_class == 1:
                sh_str_hdr = _struct.unpack_from(sh_fmt, binary_data, sh_str_offset)
                sh_str_data_off, sh_str_data_size = sh_str_hdr[4], sh_str_hdr[5]
            else:
                sh_str_hdr = _struct.unpack_from(sh_fmt, binary_data, sh_str_offset)
                sh_str_data_off, sh_str_data_size = sh_str_hdr[4], sh_str_hdr[5]
            shstrtab_data = binary_data[sh_str_data_off:sh_str_data_off + sh_str_data_size]
        except (IndexError, _struct.error):
            pass

    def _read_cstr(data: bytes, offset: int) -> str:
        end = data.find(b'\x00', offset)
        if end == -1:
            return data[offset:].decode('ascii', errors='replace')
        return data[offset:end].decode('ascii', errors='replace')

    note_indices = []
    if e_shoff > 0 and e_shentsize >= sh_fmt_size and e_shnum > 0:
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + sh_fmt_size > len(binary_data):
                break
            try:
                sh = _struct.unpack_from(sh_fmt, binary_data, off)
            except _struct.error:
                break

            if ei_class == 1:
                sh_name_idx = sh[0]
                sh_type     = sh[1]
                sh_flags    = sh[2]
                sh_addr     = sh[3]
                sh_offset   = sh[4]
                sh_size     = sh[5]
            else:
                sh_name_idx = sh[0]
                sh_type     = sh[1]
                sh_flags    = sh[2]
                sh_addr     = sh[3]
                sh_offset   = sh[4]
                sh_size     = sh[5]

            if sh_type == SHT_NULL:
                continue

            sec_name = _read_cstr(shstrtab_data, sh_name_idx) if shstrtab_data else f'<idx{i}>'

            # RWX section
            if (sh_flags & SHF_EXECINSTR) and (sh_flags & SHF_WRITE):
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'RWX_ELF_SECTION',
                    'detail': (
                        f'Section "{sec_name}" (idx={i}) has SHF_EXECINSTR|SHF_WRITE '
                        f'simultaneously — self-modifying code or injected shellcode'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })

            # High-entropy non-standard section
            if sec_name and sec_name not in _KNOWN_SECTIONS:
                if sh_size > 0:
                    sec_data = binary_data[sh_offset:sh_offset + min(sh_size, 4096)]
                    unique_bytes = len(set(sec_data)) if sec_data else 0
                    if unique_bytes > 200:
                        findings.append({
                            'severity': 'HIGH',
                            'title': 'HIGH_ENTROPY_SECTION',
                            'detail': (
                                f'Section "{sec_name}" (idx={i}) has {unique_bytes}/256 unique '
                                f'byte values — packed or encrypted payload'
                            ),
                            'host': 'localhost',
                            'port': 0,
                        })

            # Collect NOTE section indices
            if sh_type == SHT_NOTE:
                note_indices.append(i)

    # SHT_NOTE sections: flag any appearing after index 3 (unusual position)
    for ni in note_indices:
        if ni > 3:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'MISPLACED_NOTE_SECTION',
                'detail': (
                    f'SHT_NOTE section at index {ni} — standard NOTE sections appear '
                    f'near the beginning of the section table'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # ---- Program header (segment) analysis ----
    ph_fmt_size = _struct.calcsize(ph_fmt)
    PT_LOAD = 1
    PF_X = 0x1
    PF_W = 0x2
    PF_R = 0x4

    if e_phoff > 0 and e_phentsize >= ph_fmt_size and e_phnum > 0:
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + ph_fmt_size > len(binary_data):
                break
            try:
                ph = _struct.unpack_from(ph_fmt, binary_data, off)
            except _struct.error:
                break

            p_type  = ph[0]
            if ei_class == 1:
                p_flags = ph[7]
            else:
                p_flags = ph[1]

            if p_type == PT_LOAD and (p_flags & (PF_X | PF_W | PF_R)) == 7:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'RWX_LOAD_SEGMENT',
                    'detail': (
                        f'LOAD segment (idx={i}) has p_flags=7 (PF_X|PF_W|PF_R) — '
                        f'segment is readable, writable, and executable simultaneously'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })

    return findings


def detect_elf_injection_artifacts(binary_data: bytes) -> list:
    """Detect ELF injection and hooking artifacts in binary_data.

    Checks:
    - DT_PRELOAD or DT_RPATH to non-standard dir in .dynamic -> CRITICAL
    - PLT stub with >4MB GOT offset -> HIGH (hook redirect)
    - STV_HIDDEN symbol exported in .dynsym -> MEDIUM
    - Empty .symtab with non-empty .dynsym (stripped) -> MEDIUM
    - DT_TEXTREL present in .dynamic -> HIGH

    Returns list of finding dicts.
    """
    findings = []
    if len(binary_data) < 16:
        return findings
    if binary_data[:4] != b'\x7fELF':
        return findings

    ei_class = binary_data[4]
    ei_data  = binary_data[5]
    endian   = '<' if ei_data != 2 else '>'

    try:
        if ei_class == 1:
            hdr_fmt = endian + 'HHIIIIIHHHHHH'
            hdr_size = _struct.calcsize(hdr_fmt)
            if len(binary_data) < 16 + hdr_size:
                return findings
            hdr = _struct.unpack_from(hdr_fmt, binary_data, 16)
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = hdr
            sh_fmt   = endian + 'IIIIIIIIII'
            dyn_fmt  = endian + 'iI'
            sym_fmt  = endian + 'IIIBBH'
        else:
            hdr_fmt = endian + 'HHIQQQIHHHHHH'
            hdr_size = _struct.calcsize(hdr_fmt)
            if len(binary_data) < 16 + hdr_size:
                return findings
            hdr = _struct.unpack_from(hdr_fmt, binary_data, 16)
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = hdr
            sh_fmt   = endian + 'IIQQQQIIQQ'
            dyn_fmt  = endian + 'qQ'
            sym_fmt  = endian + 'IBBHQQ'
    except _struct.error:
        return findings

    sh_fmt_size  = _struct.calcsize(sh_fmt)
    dyn_fmt_size = _struct.calcsize(dyn_fmt)
    sym_fmt_size = _struct.calcsize(sym_fmt)

    SHT_DYNAMIC = 6
    SHT_DYNSYM  = 11
    SHT_SYMTAB  = 2
    SHT_NULL    = 0

    DT_NULL    = 0
    DT_RPATH   = 15
    DT_TEXTREL = 22
    DT_RUNPATH = 29
    # Non-standard: DT_PRELOAD not in standard ELF ABI;
    # some linkers encode it as DT_LOPROC+something. Scan for rpath-like paths.

    _STANDARD_RPATH_PREFIXES = (
        '/lib', '/usr/lib', '/usr/local/lib', '/lib64', '/usr/lib64',
        '/usr/x86_64', '/usr/aarch64',
    )

    STV_HIDDEN = 2

    def _parse_shdr(i):
        off = e_shoff + i * e_shentsize
        if off + sh_fmt_size > len(binary_data):
            return None
        try:
            return _struct.unpack_from(sh_fmt, binary_data, off)
        except _struct.error:
            return None

    def _sh_field(sh, field):
        """field indices differ between 32/64; unify via index into tuple."""
        return sh[field]

    # Build section index
    sections = {}
    if e_shoff > 0 and e_shentsize >= sh_fmt_size and e_shnum > 0:
        # get shstrtab
        shstrtab_data = b''
        if e_shstrndx < e_shnum:
            sh = _parse_shdr(e_shstrndx)
            if sh:
                soff = sh[4]
                ssz  = sh[5]
                shstrtab_data = binary_data[soff:soff + ssz]

        def _read_cstr(data, offset):
            end = data.find(b'\x00', offset)
            return (data[offset:end] if end != -1 else data[offset:]).decode('ascii', errors='replace')

        for i in range(e_shnum):
            sh = _parse_shdr(i)
            if sh is None:
                continue
            sh_name_idx = sh[0]
            sh_type     = sh[1]
            sh_offset   = sh[4]
            sh_size     = sh[5]
            name = _read_cstr(shstrtab_data, sh_name_idx) if shstrtab_data else ''
            sections[name] = {'type': sh_type, 'offset': sh_offset, 'size': sh_size, 'idx': i}

    # ---- .dynamic section: DT_RPATH, DT_RUNPATH, DT_TEXTREL ----
    dynstrtab_data = b''
    if '.dynstr' in sections:
        ds = sections['.dynstr']
        dynstrtab_data = binary_data[ds['offset']:ds['offset'] + ds['size']]

    def _read_cstr(data, offset):
        end = data.find(b'\x00', offset)
        return (data[offset:end] if end != -1 else data[offset:]).decode('ascii', errors='replace')

    dynamic_sec = sections.get('.dynamic')
    if dynamic_sec and dynamic_sec['size'] > 0:
        doff = dynamic_sec['offset']
        dsz  = dynamic_sec['size']
        pos  = 0
        while pos + dyn_fmt_size <= dsz:
            try:
                entry = _struct.unpack_from(dyn_fmt, binary_data, doff + pos)
            except _struct.error:
                break
            d_tag = entry[0]
            d_val = entry[1]
            pos += dyn_fmt_size

            if d_tag == DT_NULL:
                break

            if d_tag in (DT_RPATH, DT_RUNPATH):
                if dynstrtab_data and d_val < len(dynstrtab_data):
                    rpath_str = _read_cstr(dynstrtab_data, d_val)
                    if rpath_str and not any(rpath_str.startswith(p) for p in _STANDARD_RPATH_PREFIXES):
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'ELF_PRELOAD_HIJACK',
                            'detail': (
                                f'DT_{"RPATH" if d_tag == DT_RPATH else "RUNPATH"} points to '
                                f'non-standard directory: "{rpath_str}" — library search hijack'
                            ),
                            'host': 'localhost',
                            'port': 0,
                        })

            if d_tag == DT_TEXTREL:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'TEXTREL_SET',
                    'detail': (
                        'DT_TEXTREL present in .dynamic — .text section is writable during '
                        'dynamic linking (PIC violation, code injection surface)'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })

    # ---- PLT stub GOT offset check ----
    plt_sec = sections.get('.plt')
    got_sec = sections.get('.got.plt') or sections.get('.got')
    if plt_sec and got_sec:
        plt_vma = plt_sec.get('addr', plt_sec['offset'])
        got_vma = got_sec.get('addr', got_sec['offset'])
        offset_dist = abs(got_vma - plt_vma) if got_vma and plt_vma else 0
        if offset_dist > 4 * 1024 * 1024:
            findings.append({
                'severity': 'HIGH',
                'title': 'PLT_GOT_REDIRECT',
                'detail': (
                    f'PLT/GOT distance is {offset_dist // 1024}KB (>4MB) — '
                    f'GOT entry may have been redirected by a hook or injected library'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # ---- .dynsym: STV_HIDDEN but in dynsym (exported) ----
    dynsym_sec = sections.get('.dynsym')
    if dynsym_sec and dynsym_sec['size'] >= sym_fmt_size:
        soff = dynsym_sec['offset']
        ssz  = dynsym_sec['size']
        count = ssz // sym_fmt_size
        hidden_exported = 0
        for i in range(count):
            try:
                sym = _struct.unpack_from(sym_fmt, binary_data, soff + i * sym_fmt_size)
            except _struct.error:
                break
            if ei_class == 1:
                # Elf32_Sym: st_name, st_value, st_size, st_info, st_other, st_shndx
                st_other = sym[4]
            else:
                # Elf64_Sym: st_name, st_info, st_other, st_shndx, st_value, st_size
                st_other = sym[2]
            visibility = st_other & 0x3
            if visibility == STV_HIDDEN:
                hidden_exported += 1
        if hidden_exported > 0:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'HIDDEN_EXPORTED_SYMBOL',
                'detail': (
                    f'{hidden_exported} symbol(s) in .dynsym have STV_HIDDEN visibility — '
                    f'symbol is hidden from linker but present in dynamic symbol table'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # ---- Stripped: empty .symtab + non-empty .dynsym ----
    symtab_sec = sections.get('.symtab')
    has_dynsym = dynsym_sec is not None and dynsym_sec['size'] > 0
    symtab_empty = (symtab_sec is None) or (symtab_sec['size'] == 0)
    if symtab_empty and has_dynsym:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'STRIPPED_WITH_DYNSYM',
            'detail': (
                '.symtab absent/empty but .dynsym present — binary stripped of debug '
                'symbols while retaining dynamic linkage (common in malware)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_ptrace_instrumentation(pid=None) -> list:
    """Detect DBI/ptrace instrumentation on running processes.

    Checks /proc/{pid}/maps and /proc/{pid}/status for:
    - Valgrind vgpreload_* paths -> HIGH
    - PIN DBI paths (pin-3/source) -> HIGH
    - TracerPid != 0 -> HIGH
    - ASan/MSan/TSan sanitizer runtime -> MEDIUM

    If pid=None, scan all /proc/[0-9]+ directories.

    Returns list of finding dicts.
    """
    findings = []

    import re as _re

    _VALGRIND_PAT  = _re.compile(r'vgpreload_', _re.IGNORECASE)
    _PIN_PAT       = _re.compile(r'pin-\d+/source|pin\.so|pintools', _re.IGNORECASE)
    _SANITIZER_PAT = _re.compile(r'lib(a|m|t|ub)san', _re.IGNORECASE)

    def _scan_pid(p):
        proc_maps  = f'/proc/{p}/maps'
        proc_status = f'/proc/{p}/status'

        # TracerPid
        try:
            with open(proc_status) as fh:
                for line in fh:
                    if line.startswith('TracerPid:'):
                        tracer = int(line.split(':', 1)[1].strip())
                        if tracer != 0:
                            findings.append({
                                'severity': 'HIGH',
                                'title': 'PROCESS_BEING_TRACED',
                                'detail': (
                                    f'pid={p} has TracerPid={tracer} — '
                                    f'process is being ptraced/debugged'
                                ),
                                'host': 'localhost',
                                'port': 0,
                            })
                        break
        except OSError:
            pass

        # Maps scan
        try:
            with open(proc_maps) as fh:
                for line in fh:
                    if _VALGRIND_PAT.search(line):
                        findings.append({
                            'severity': 'HIGH',
                            'title': 'VALGRIND_INSTRUMENTATION_DETECTED',
                            'detail': (
                                f'pid={p}: Valgrind memcheck preload detected in maps — '
                                f'memory analysis / taint tracking active'
                            ),
                            'host': 'localhost',
                            'port': 0,
                        })
                        break
        except OSError:
            pass

        try:
            with open(proc_maps) as fh:
                for line in fh:
                    if _PIN_PAT.search(line):
                        findings.append({
                            'severity': 'HIGH',
                            'title': 'PIN_DBI_DETECTED',
                            'detail': (
                                f'pid={p}: Intel PIN DBI path found in maps — '
                                f'syscall/instruction tracing active'
                            ),
                            'host': 'localhost',
                            'port': 0,
                        })
                        break
        except OSError:
            pass

        try:
            with open(proc_maps) as fh:
                for line in fh:
                    if _SANITIZER_PAT.search(line):
                        findings.append({
                            'severity': 'MEDIUM',
                            'title': 'SANITIZER_RUNTIME_LOADED',
                            'detail': (
                                f'pid={p}: ASan/MSan/TSan/UBSan runtime .so found in maps — '
                                f'sanitizer instrumentation active (debug/CI build)'
                            ),
                            'host': 'localhost',
                            'port': 0,
                        })
                        break
        except OSError:
            pass

    if pid is not None:
        _scan_pid(pid)
    else:
        try:
            for entry in os.scandir('/proc'):
                if entry.is_dir() and entry.name.isdigit():
                    _scan_pid(int(entry.name))
        except OSError:
            pass

    return findings


def detect_binary_packing_indicators(binary_data: bytes) -> list:
    """Detect binary packing and obfuscation indicators.

    Checks:
    - UPX magic b"UPX!" -> HIGH
    - Low printable string density (<5 strings/1000 bytes) -> MEDIUM
    - Unusual section name (>8 chars, mixed case, no vowels) -> MEDIUM
    - ELF entry point outside .text section range -> HIGH

    Returns list of finding dicts.
    """
    findings = []
    if not binary_data:
        return findings

    # ---- UPX magic ----
    if b'\x55\x50\x58\x21' in binary_data:  # UPX!
        findings.append({
            'severity': 'HIGH',
            'title': 'UPX_PACKED_BINARY',
            'detail': (
                'UPX magic bytes (UPX!) found — binary is packed with UPX; '
                'original code is compressed and unpacked at runtime'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- String density ----
    import re as _re
    printable_runs = _re.findall(rb'[ -~]{4,}', binary_data)
    data_kb = len(binary_data) / 1000.0
    density = len(printable_runs) / data_kb if data_kb > 0 else 0
    if density < 5.0 and len(binary_data) > 1024:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'LOW_STRING_DENSITY',
            'detail': (
                f'{len(printable_runs)} printable-ASCII runs (>4 chars) in '
                f'{len(binary_data)} bytes ({density:.2f}/KB) — '
                f'below 5/KB threshold, consistent with packed or obfuscated binary'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- ELF-specific checks ----
    if len(binary_data) < 16 or binary_data[:4] != b'\x7fELF':
        return findings

    ei_class = binary_data[4]
    ei_data  = binary_data[5]
    endian   = '<' if ei_data != 2 else '>'

    _VOWELS = set('aeiouAEIOU')

    try:
        if ei_class == 1:
            hdr_fmt = endian + 'HHIIIIIHHHHHH'
            hdr_size = _struct.calcsize(hdr_fmt)
            if len(binary_data) < 16 + hdr_size:
                return findings
            hdr = _struct.unpack_from(hdr_fmt, binary_data, 16)
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = hdr
            sh_fmt = endian + 'IIIIIIIIII'
        else:
            hdr_fmt = endian + 'HHIQQQIHHHHHH'
            hdr_size = _struct.calcsize(hdr_fmt)
            if len(binary_data) < 16 + hdr_size:
                return findings
            hdr = _struct.unpack_from(hdr_fmt, binary_data, 16)
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = hdr
            sh_fmt = endian + 'IIQQQQIIQQ'
    except _struct.error:
        return findings

    sh_fmt_size = _struct.calcsize(sh_fmt)

    # Parse shstrtab
    shstrtab_data = b''
    if (e_shstrndx != 0xffff and e_shstrndx < e_shnum and
            e_shoff > 0 and e_shentsize >= sh_fmt_size):
        off = e_shoff + e_shstrndx * e_shentsize
        try:
            sh = _struct.unpack_from(sh_fmt, binary_data, off)
            soff, ssz = sh[4], sh[5]
            shstrtab_data = binary_data[soff:soff + ssz]
        except (IndexError, _struct.error):
            pass

    def _read_cstr(data, offset):
        end = data.find(b'\x00', offset)
        return (data[offset:end] if end != -1 else data[offset:]).decode('ascii', errors='replace')

    text_addr = None
    text_size = 0

    if e_shoff > 0 and e_shentsize >= sh_fmt_size and e_shnum > 0:
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + sh_fmt_size > len(binary_data):
                break
            try:
                sh = _struct.unpack_from(sh_fmt, binary_data, off)
            except _struct.error:
                break

            sh_name_idx = sh[0]
            sh_addr     = sh[3]
            sh_size     = sh[5]
            sec_name = _read_cstr(shstrtab_data, sh_name_idx) if shstrtab_data else ''

            # Track .text for entry point check
            if sec_name == '.text':
                text_addr = sh_addr
                text_size = sh_size

            # Unusual section name heuristic
            # Skip empty/standard section names; flag long, mixed-case, vowel-free names
            if sec_name and sec_name[0] != '.' and len(sec_name) > 8:
                has_upper = any(c.isupper() for c in sec_name)
                has_lower = any(c.islower() for c in sec_name)
                no_vowels = not any(c in _VOWELS for c in sec_name)
                if has_upper and has_lower and no_vowels:
                    findings.append({
                        'severity': 'MEDIUM',
                        'title': 'UNUSUAL_SECTION_NAME',
                        'detail': (
                            f'Section name "{sec_name}" (idx={i}) is >8 chars, mixed-case, '
                            f'and contains no vowels — random-looking name consistent with packing'
                        ),
                        'host': 'localhost',
                        'port': 0,
                    })

    # Entry point outside .text
    if text_addr is not None and text_size > 0 and e_entry > 0:
        if not (text_addr <= e_entry < text_addr + text_size):
            findings.append({
                'severity': 'HIGH',
                'title': 'ENTRY_POINT_OUTSIDE_TEXT',
                'detail': (
                    f'ELF e_entry=0x{e_entry:x} is outside .text '
                    f'(0x{text_addr:x}–0x{text_addr + text_size:x}) — '
                    f'entry points to a non-standard section, consistent with packing/injection'
                ),
                'host': 'localhost',
                'port': 0,
            })

    return findings


def detect_elf_virus_infection(binary_data: bytes) -> list:
    """Detect ELF virus infection markers in binary_data.

    Checks:
    - PT_NOTE segment with PF_R|PF_X flags (p_type=4, p_flags=5):
      classic virus technique converting PT_NOTE to executable PT_LOAD -> CRITICAL
    - Entry point outside first PT_LOAD segment [p_vaddr, p_vaddr+p_filesz]:
      text segment padding virus redirects entry to parasite -> HIGH
    - First PT_LOAD segment p_offset > 0 (not at file start):
      reverse text infection prepends parasite before binary image -> HIGH
    - Executable segment p_filesz > file size + 10MB:
      possible shellcode padding or phantom segment -> MEDIUM

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings = []
    if len(binary_data) < 16:
        return findings
    if binary_data[:4] != b'\x7fELF':
        return findings

    ei_class = binary_data[4]  # 1=32-bit, 2=64-bit
    ei_data  = binary_data[5]  # 1=LE, 2=BE
    endian   = '<' if ei_data != 2 else '>'

    PT_LOAD = 1
    PT_NOTE = 4
    PF_X    = 0x1
    PF_R    = 0x4
    PF_RX   = PF_R | PF_X  # 5 — read+execute without write

    try:
        if ei_class == 1:
            # 32-bit ELF header
            hdr_fmt = endian + 'HHIIIIIHHHHHH'
            hdr_size = _struct.calcsize(hdr_fmt)
            if len(binary_data) < 16 + hdr_size:
                return findings
            hdr = _struct.unpack_from(hdr_fmt, binary_data, 16)
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = hdr
            # Elf32_Phdr: p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
            ph_fmt = endian + 'IIIIIIII'
        else:
            # 64-bit ELF header
            hdr_fmt = endian + 'HHIQQQIHHHHHH'
            hdr_size = _struct.calcsize(hdr_fmt)
            if len(binary_data) < 16 + hdr_size:
                return findings
            hdr = _struct.unpack_from(hdr_fmt, binary_data, 16)
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = hdr
            # Elf64_Phdr: p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
            ph_fmt = endian + 'IIQQQQQQ'
    except _struct.error:
        return findings

    ph_fmt_size = _struct.calcsize(ph_fmt)
    if e_phoff == 0 or e_phnum == 0 or e_phentsize < ph_fmt_size:
        return findings

    file_size         = len(binary_data)
    first_load_vaddr  = None
    first_load_filesz = None
    first_load_offset = None

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + ph_fmt_size > file_size:
            break
        try:
            ph = _struct.unpack_from(ph_fmt, binary_data, off)
        except _struct.error:
            break

        if ei_class == 1:
            # 32-bit Phdr field order: type, offset, vaddr, paddr, filesz, memsz, flags, align
            p_type   = ph[0]
            p_offset = ph[1]
            p_vaddr  = ph[2]
            p_filesz = ph[4]
            p_flags  = ph[6]
        else:
            # 64-bit Phdr field order: type, flags, offset, vaddr, paddr, filesz, memsz, align
            p_type   = ph[0]
            p_flags  = ph[1]
            p_offset = ph[2]
            p_vaddr  = ph[3]
            p_filesz = ph[5]

        # Check 1: PT_NOTE with PF_R|PF_X — converted to executable segment by virus
        if p_type == PT_NOTE and (p_flags & PF_RX) == PF_RX:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'PT_NOTE_TO_LOAD_INFECTION',
                'detail': (
                    f'Program header {i}: p_type=PT_NOTE(4) but p_flags=0x{p_flags:x} '
                    f'includes PF_R|PF_X — classic ELF virus technique; PT_NOTE converted '
                    f'to executable segment at p_offset=0x{p_offset:x} to host parasite code'
                ),
                'host': 'localhost',
                'port': 0,
            })

        # Track first PT_LOAD for entry-point and reverse-text checks
        if p_type == PT_LOAD and first_load_vaddr is None:
            first_load_vaddr  = p_vaddr
            first_load_filesz = p_filesz
            first_load_offset = p_offset

        # Check 4: Executable segment more than 10MB larger than the on-disk file
        if (p_flags & PF_X) and p_filesz > file_size + 10 * 1024 * 1024:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'LARGE_EXECUTABLE_SEGMENT',
                'detail': (
                    f'Program header {i}: executable segment p_filesz=0x{p_filesz:x} '
                    f'({p_filesz // (1024 * 1024)}MB) exceeds file size '
                    f'{file_size // (1024 * 1024)}MB by >10MB — '
                    f'possible shellcode padding or phantom segment declaration'
                ),
                'host': 'localhost',
                'port': 0,
            })

    if first_load_vaddr is not None:
        # Check 2: Entry point outside first PT_LOAD segment range
        load_end = first_load_vaddr + first_load_filesz
        if e_entry > 0 and not (first_load_vaddr <= e_entry < load_end):
            findings.append({
                'severity': 'HIGH',
                'title': 'ENTRY_POINT_REDIRECTED',
                'detail': (
                    f'e_entry=0x{e_entry:x} falls outside first PT_LOAD segment '
                    f'[0x{first_load_vaddr:x}, 0x{load_end:x}) — '
                    f'text segment padding virus redirects execution to injected parasite'
                ),
                'host': 'localhost',
                'port': 0,
            })

        # Check 3: Reverse text infection — first LOAD not at file offset 0
        if first_load_offset > 0:
            findings.append({
                'severity': 'HIGH',
                'title': 'REVERSE_TEXT_INFECTION',
                'detail': (
                    f'First PT_LOAD segment p_offset=0x{first_load_offset:x} (expected 0) — '
                    f'reverse text infection prepends parasite code before the original '
                    f'binary in the file; ELF header offset shifted to accommodate prepend'
                ),
                'host': 'localhost',
                'port': 0,
            })

    return findings


def detect_dll_injection_traces(binary_data: bytes) -> list:
    """Detect DLL/shared library injection traces in ELF binary_data.

    Checks:
    - DT_NEEDED entry whose string contains /tmp/, /dev/shm/, or /var/tmp/ -> CRITICAL
    - Multiple DT_RPATH path components that are write-accessible on disk -> HIGH
    - Literal string "LD_PRELOAD" present anywhere in the binary -> HIGH
    - DT_RUNPATH component that is world-writable on disk -> CRITICAL

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    # LD_PRELOAD string scan — no ELF parsing required; works on any binary
    if b'LD_PRELOAD' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title': 'LD_PRELOAD_REFERENCED',
            'detail': (
                'Literal string "LD_PRELOAD" found in binary — binary references the '
                'preload injection mechanism; may manipulate or persist a preloaded library'
            ),
            'host': 'localhost',
            'port': 0,
        })

    if len(binary_data) < 16 or binary_data[:4] != b'\x7fELF':
        return findings

    ei_class = binary_data[4]
    ei_data  = binary_data[5]
    endian   = '<' if ei_data != 2 else '>'

    DT_NULL    = 0
    DT_NEEDED  = 1
    DT_RPATH   = 15
    DT_RUNPATH = 29

    _SUSPICIOUS_PREFIXES = ('/tmp/', '/dev/shm/', '/var/tmp/')

    try:
        if ei_class == 1:
            hdr_fmt = endian + 'HHIIIIIHHHHHH'
            hdr_size = _struct.calcsize(hdr_fmt)
            if len(binary_data) < 16 + hdr_size:
                return findings
            hdr = _struct.unpack_from(hdr_fmt, binary_data, 16)
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = hdr
            sh_fmt  = endian + 'IIIIIIIIII'
            dyn_fmt = endian + 'iI'
        else:
            hdr_fmt = endian + 'HHIQQQIHHHHHH'
            hdr_size = _struct.calcsize(hdr_fmt)
            if len(binary_data) < 16 + hdr_size:
                return findings
            hdr = _struct.unpack_from(hdr_fmt, binary_data, 16)
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = hdr
            sh_fmt  = endian + 'IIQQQQIIQQ'
            dyn_fmt = endian + 'qQ'
    except _struct.error:
        return findings

    sh_fmt_size  = _struct.calcsize(sh_fmt)
    dyn_fmt_size = _struct.calcsize(dyn_fmt)

    # Parse section headers -> build name -> {offset, size} map
    def _parse_shdr(idx):
        off = e_shoff + idx * e_shentsize
        if off + sh_fmt_size > len(binary_data):
            return None
        try:
            return _struct.unpack_from(sh_fmt, binary_data, off)
        except _struct.error:
            return None

    def _read_cstr(data, offset):
        end = data.find(b'\x00', offset)
        return (data[offset:end] if end != -1 else data[offset:]).decode('ascii', errors='replace')

    sections = {}
    if e_shoff > 0 and e_shentsize >= sh_fmt_size and e_shnum > 0:
        shstrtab_data = b''
        if e_shstrndx != 0xffff and e_shstrndx < e_shnum:
            sh = _parse_shdr(e_shstrndx)
            if sh:
                shstrtab_data = binary_data[sh[4]:sh[4] + sh[5]]
        for i in range(e_shnum):
            sh = _parse_shdr(i)
            if sh is None:
                continue
            name = _read_cstr(shstrtab_data, sh[0]) if shstrtab_data else ''
            sections[name] = {'offset': sh[4], 'size': sh[5]}

    # Resolve .dynstr (string table backing .dynamic entries)
    dynstrtab_data = b''
    dynstr_sec = sections.get('.dynstr')
    if dynstr_sec:
        dynstrtab_data = binary_data[dynstr_sec['offset']:dynstr_sec['offset'] + dynstr_sec['size']]

    dynamic_sec = sections.get('.dynamic')
    if not dynamic_sec or dynamic_sec['size'] == 0 or not dynstrtab_data:
        return findings

    rpath_writable = []
    doff = dynamic_sec['offset']
    dsz  = dynamic_sec['size']
    pos  = 0

    while pos + dyn_fmt_size <= dsz:
        try:
            entry = _struct.unpack_from(dyn_fmt, binary_data, doff + pos)
        except _struct.error:
            break
        d_tag = entry[0]
        d_val = entry[1]
        pos += dyn_fmt_size

        if d_tag == DT_NULL:
            break

        if d_tag not in (DT_NEEDED, DT_RPATH, DT_RUNPATH):
            continue
        if d_val >= len(dynstrtab_data):
            continue

        path_str = _read_cstr(dynstrtab_data, d_val)

        if d_tag == DT_NEEDED:
            # DT_NEEDED holding a full path into /tmp, /dev/shm, /var/tmp
            if any(path_str.startswith(sus) or sus in path_str for sus in _SUSPICIOUS_PREFIXES):
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'SUSPICIOUS_NEEDED_PATH',
                    'detail': (
                        f'DT_NEEDED="{path_str}" references a suspicious transient path — '
                        f'legitimate shared libraries do not reside in /tmp, /dev/shm, or '
                        f'/var/tmp; indicates an injected shared library'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })

        elif d_tag == DT_RPATH:
            # Collect write-accessible components across all DT_RPATH entries
            for component in path_str.split(':'):
                component = component.strip()
                if component and os.access(component, os.W_OK):
                    rpath_writable.append(component)

        elif d_tag == DT_RUNPATH:
            # Flag any world-writable component in DT_RUNPATH
            for component in path_str.split(':'):
                component = component.strip()
                if not component:
                    continue
                try:
                    st = os.stat(component)
                    if st.st_mode & 0o002:  # world-writable bit
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'WRITABLE_RUNPATH',
                            'detail': (
                                f'DT_RUNPATH component "{component}" is world-writable '
                                f'(mode 0o{st.st_mode & 0o777:o}) — any local user can '
                                f'plant a malicious library; dynamic linker will prefer '
                                f'DT_RUNPATH over LD_LIBRARY_PATH'
                            ),
                            'host': 'localhost',
                            'port': 0,
                        })
                except OSError:
                    pass

    # Multiple write-accessible DT_RPATH components -> injection indicator
    if len(rpath_writable) >= 2:
        findings.append({
            'severity': 'HIGH',
            'title': 'MULTIPLE_RPATH_INJECTION',
            'detail': (
                f'{len(rpath_writable)} write-accessible DT_RPATH path components: '
                f'{", ".join(rpath_writable[:4])} — '
                f'multiple writable rpath entries enable persistent library preloading '
                f'without LD_PRELOAD; deprecated DT_RPATH takes priority over LD_LIBRARY_PATH'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_named_pipe_abuse(binary_data: bytes) -> list:
    """Detect Windows named pipe usage patterns in binary_data.

    Sourced from: Practical Malware Analysis ch7 (Following Running Malware —
    Services/Threads/Pipes), appendix A (Important Windows Functions).
    Named pipes are the primary Windows IPC mechanism abused for C2 channels,
    reverse shells (CreateProcess stdout->pipe->socket), and lateral movement.

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    # UNC named pipe path prefix: \\.\pipe\
    if re.search(rb'\\\\.\\pipe\\', binary_data, re.IGNORECASE):
        findings.append({
            'severity': 'HIGH',
            'title': 'NAMED_PIPE_USAGE',
            'detail': (
                r'Named pipe path prefix "\\.\pipe\" found in binary — '
                'indicates IPC or lateral movement via Windows named pipes; '
                'malware redirects shell I/O through pipe to socket for '
                'agentless C2 (PMA ch7: CreateProcess + STARTUPINFO pipe handles)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # CreateNamedPipe API — server-side pipe creation
    if re.search(rb'CreateNamedPipe[AW]?', binary_data):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'NAMED_PIPE_SERVER',
            'detail': (
                '"CreateNamedPipe" API reference detected — binary creates a named pipe '
                'server endpoint; primary mechanism for malware C2 channels and process '
                'injection staging; paired with ConnectNamedPipe to receive attacker '
                'commands (PMA ch7)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ConnectNamedPipe — server blocks waiting for a client
    if b'ConnectNamedPipe' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title': 'NAMED_PIPE_CONNECT',
            'detail': (
                '"ConnectNamedPipe" API reference detected — server-side call that blocks '
                'until a client connects; indicates C2 staging or tool orchestration pipe; '
                'typical in remote-shell implants pairing pipe I/O with CreateProcess '
                'socket redirection (PMA ch7)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # TransactNamedPipe — bidirectional IPC in a single call
    if b'TransactNamedPipe' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title': 'NAMED_PIPE_TRANSACT',
            'detail': (
                '"TransactNamedPipe" API reference detected — single call writes then '
                'reads data over a named pipe; used in living-off-the-land lateral '
                'movement and reverse-shell I/O redirection; also present in '
                'PeekNamedPipe-based C2 polling variants (PMA appendix A)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # Privileged RPC pipe names known from credential/service attack tooling
    _sensitive = [
        (rb'\\pipe\\lsass',  'LSASS pipe — credential access via LSASS named pipe RPC channel'),
        (rb'\\pipe\\svcctl', 'SVCCTL pipe — remote service control manager RPC; enables service install/start'),
        (rb'\\pipe\\samr',   'SAMR pipe — SAM database RPC; used for credential and account enumeration'),
    ]
    for pattern, context in _sensitive:
        if re.search(pattern, binary_data, re.IGNORECASE):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'SENSITIVE_PIPE_NAME',
                'detail': (
                    f'{context}; privileged RPC pipe string in binary confirms '
                    f'credential/service manipulation capability (PMA ch7, appendix A)'
                ),
                'host': 'localhost',
                'port': 0,
            })

    return findings


def detect_windows_service_manipulation(binary_data: bytes) -> list:
    """Detect Windows service control manager API usage in binary_data.

    Sourced from: Practical Malware Analysis ch7 (Services — OpenSCManager,
    CreateService, StartService), ch11 (Persistence Mechanisms — SvcHost DLLs,
    service-group hijacking, netsvcs overwrite pattern).

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    # OpenSCManager / OpenServiceA/W — prerequisite handle for all SCM operations
    if re.search(rb'OpenSCManager[AW]?', binary_data) or re.search(rb'OpenService[AW]?', binary_data):
        findings.append({
            'severity': 'HIGH',
            'title': 'SERVICE_CONTROL_MANAGER_ACCESS',
            'detail': (
                '"OpenSCManager" or "OpenService" API reference detected — '
                'all service install/modify/control operations require this handle first; '
                'confirms binary interacts with the Windows service control manager '
                '(PMA ch7: "All code that will interact with services will call this function")'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # CreateService — new service registration; SYSTEM-level persistence
    create_pos = -1
    m = re.search(rb'CreateService[AW]?', binary_data)
    if m:
        create_pos = m.start()
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SERVICE_CREATION',
            'detail': (
                '"CreateService" API reference detected — binary registers a new Windows '
                'service; survives reboot and may run as SYSTEM without user interaction; '
                'malware targets netsvcs group to blend into normal svchost.exe process '
                'tree (PMA ch7/ch11: WIN32_SHARE_PROCESS type avoids separate Task Manager entry)'
            ),
            'host': 'localhost',
            'port': 0,
        })

        # StartService within 256 bytes of CreateService — immediate activation
        window = binary_data[create_pos:create_pos + 256]
        if re.search(rb'StartService[AW]?', window):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'IMMEDIATE_SERVICE_START',
                'detail': (
                    '"StartService" appears within 256 bytes of "CreateService" — binary '
                    'creates then immediately starts the service; rapid persistence '
                    'installation activates payload before reboot-based detection window; '
                    'StartService used only for manually-started services, confirming '
                    'deliberate same-session activation (PMA ch7)'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # ChangeServiceConfig / ChangeServiceConfig2 — hijack existing service
    if re.search(rb'ChangeServiceConfig', binary_data):
        findings.append({
            'severity': 'HIGH',
            'title': 'SERVICE_CONFIG_MODIFICATION',
            'detail': (
                '"ChangeServiceConfig" or "ChangeServiceConfig2" API reference detected — '
                'binary modifies an existing service configuration; malware overwrites '
                'rarely-used services to avoid creating detectable new entries; '
                'ImagePath or ServiceDLL substitution achieves persistence without '
                'new registry keys (PMA ch11: netsvcs group hijack pattern)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # DeleteService — anti-forensic cleanup after payload delivery
    if re.search(rb'DeleteService', binary_data):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SERVICE_DELETION',
            'detail': (
                '"DeleteService" API reference detected — binary removes a service entry; '
                'anti-forensics pattern: install service for privilege escalation or '
                'lateral movement, then delete after payload delivery to reduce forensic '
                'footprint and evade persistence-focused detection (PMA ch7/ch11)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_heap_spray_patterns(binary_data: bytes) -> list:
    """Detect heap spray attack setup patterns in binary_data.

    Sourced from: Practical Malware Analysis ch19 (Shellcode Analysis — NOP sleds,
    heap spray landing addresses), ch16 (Anti-Debugging — interfering with heap
    allocator flags), and ch8/ch9 (Debugging — heap allocation breakpoints in OllyDbg).
    Heap spray fills large heap regions with shellcode + NOP sleds so that any
    redirected execution pointer lands in the sled and reaches the payload.

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    import struct

    findings = []
    if not binary_data:
        return findings

    # Large heap allocation constant >= 0x1000000 (16MB) near HeapAlloc
    # Spray allocates enormous blocks to guarantee predictable placement in address space
    heap_alloc_positions = [m.start() for m in re.finditer(rb'HeapAlloc', binary_data)]
    if heap_alloc_positions:
        large_alloc_found = False
        for pos in heap_alloc_positions:
            # Scan 128-byte window around each HeapAlloc reference for large size constants
            window_start = max(0, pos - 64)
            window_end = min(len(binary_data), pos + 64)
            window = binary_data[window_start:window_end]
            for i in range(len(window) - 3):
                val = struct.unpack_from('<I', window, i)[0]
                if 0x1000000 <= val <= 0x80000000:
                    large_alloc_found = True
                    break
            if large_alloc_found:
                break
        if large_alloc_found:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'HEAP_SPRAY_ALLOCATION',
                'detail': (
                    '"HeapAlloc" API reference detected with size argument >= 16MB (0x1000000) '
                    'in the surrounding instruction window — large single-block heap allocation '
                    'is the defining primitive of a heap spray; attacker fills virtual address '
                    'space so that a corrupted pointer landing anywhere in the spray region '
                    'slides through a NOP sled and reaches shellcode; '
                    'heap debug flags (ForceFlags/NTGlobalFlag at PEB+0x68) interfere with '
                    'heap spray sizing under debuggers, which is why spray malware checks '
                    'PEB.BeingDebugged before calling HeapAlloc '
                    '(PMA ch19: NOP sled layout; ch16: ProcessHeap/NTGlobalFlag debug detection)'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # Repeated HeapAlloc calls (>20 occurrences) near VirtualAlloc — heap spray setup loop
    # Two-phase pattern: VirtualAlloc reserves contiguous region; HeapAlloc loop fills it
    heap_alloc_count = len(heap_alloc_positions)
    if heap_alloc_count > 20 and re.search(rb'VirtualAlloc', binary_data):
        findings.append({
            'severity': 'HIGH',
            'title': 'REPEATED_HEAP_ALLOCATION',
            'detail': (
                f'"HeapAlloc" reference appears {heap_alloc_count} times and "VirtualAlloc" '
                'is also present — repeated small heap allocations adjacent to virtual memory '
                'reservation matches the two-phase heap spray pattern: VirtualAlloc reserves '
                'a large contiguous region and the HeapAlloc loop fills it with payload copies '
                'to maximize coverage of guessed instruction pointer values; '
                'OllyDbg heap allocation breakpoints (Alt+M memory map -> right-click) '
                'are the standard tool for catching spray loops mid-flight '
                '(PMA ch9: OllyDbg memory map and heap breakpoints; ch19: shellcode staging)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # NOP sled (16+ consecutive 0x90 bytes) within 512 bytes of HeapAlloc
    # Sled precedes shellcode so any landing point in the spray region eventually hits payload
    nop_match = re.search(rb'\x90{16,}', binary_data)
    if nop_match and heap_alloc_positions:
        nop_pos = nop_match.start()
        for hpos in heap_alloc_positions:
            if abs(hpos - nop_pos) <= 512:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'HEAP_SPRAY_SHELLCODE_STAGING',
                    'detail': (
                        'NOP sled (16+ consecutive 0x90 bytes) found within 512 bytes of a '
                        '"HeapAlloc" reference — classic heap spray shellcode staging: sled '
                        'absorbs imprecise instruction pointer redirections, guiding execution '
                        'to the following payload regardless of exact landing offset; '
                        'NOP alternatives in 0x40-0x4f range (INC/DEC register single-byte '
                        'opcodes) are substituted when the exploit must pass printable-ASCII '
                        'filters on the spray buffer '
                        '(PMA ch19: NOP sled and shellcode layout — "NOP sled and shellcode layout")'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
                break

    # Predictable heap spray landing address constants: 0x0c0c0c0c, 0x0d0d0d0d, 0x0a0a0a0a
    # Attacker overwrites a function pointer with a constant known to reside in the spray region
    spray_constants = {
        b'\x0c\x0c\x0c\x0c': '0x0c0c0c0c',
        b'\x0d\x0d\x0d\x0d': '0x0d0d0d0d',
        b'\x0a\x0a\x0a\x0a': '0x0a0a0a0a',
    }
    for pattern, label in spray_constants.items():
        if pattern in binary_data:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'HEAP_SPRAY_CONSTANT',
                'detail': (
                    f'Heap spray landing address constant {label} found in binary — '
                    'attacker overwrites a code pointer with this value because the spray '
                    'fills memory at this predictable address; 0x0c0c0c0c dominates browser '
                    'heap sprays targeting JIT regions; presence in a binary strongly '
                    'indicates pre-spray pointer overwrite or spray-aware exploit staging '
                    '(PMA ch19: shellcode landing addresses; ch8: OllyDbg memory view '
                    'for locating spray constants in the heap)'
                ),
                'host': 'localhost',
                'port': 0,
            })
            break

    return findings


def detect_rop_chain_indicators(binary_data: bytes) -> list:
    """Detect Return-Oriented Programming (ROP) chain construction patterns.

    Sourced from: Practical Malware Analysis ch9 (OllyDbg — tracing, RETN gadget
    step-through in the disassembly pane), ch16 (Anti-Debugging — stack manipulation
    and exception-based control flow redirection), ch19 (Shellcode Analysis —
    position-independent code and DEP bypass), and appendix A (VirtualProtect/
    VirtualAlloc as the standard ROP payload for DEP defeat).
    ROP repurposes existing executable code sequences ending in RETN (0xC3) to build
    arbitrary computation without injecting new executable bytes, defeating DEP.

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    # RETN gadget density: >50 RETN (0xC3) bytes in any 1KB sliding window
    # High RETN density indicates a gadget table, trampoline region, or ROP dispatcher
    window_size = 1024
    high_density_found = False
    if len(binary_data) >= window_size:
        for start in range(0, len(binary_data) - window_size, 256):
            if binary_data[start:start + window_size].count(b'\xc3') > 50:
                high_density_found = True
                break
    if high_density_found:
        findings.append({
            'severity': 'HIGH',
            'title': 'HIGH_RET_DENSITY',
            'detail': (
                'More than 50 RETN instructions (0xC3) found within a 1KB window — '
                'elevated RET density is a structural marker of ROP gadget regions; '
                'ROP chains stitch together short code sequences each ending in RETN '
                'so the CPU stack-driven dispatch mechanism acts as the interpreter; '
                'high-density regions are candidate gadget tables, trampoline stubs, '
                'or sections harvested by a ROP gadget finder (mona.py, ROPgadget); '
                'OllyDbg tracing (Ctrl+F11 step-into mode) through such a region '
                'shows each RETN dispatching to the next gadget address on the stack '
                '(PMA ch9: OllyDbg tracing; ch19: shellcode position-independent code)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # Stack pivot gadgets: XCHG/MOV/POP ESP near RETN
    # Pivot redirects ESP to attacker-controlled memory, loading the ROP chain into CPU dispatch
    stack_pivot_patterns = [
        (rb'\x94\xc3', 'XCHG EAX,ESP + RETN (0x94 0xC3)'),
        (rb'\x5c\xc3', 'POP ESP + RETN (0x5C 0xC3)'),
        (rb'\x87\xdc\xc3', 'XCHG EBX,ESP + RETN (0x87 0xDC 0xC3)'),
        (rb'\x8b\xe4\xc3', 'MOV ESP,ESP-frame + RETN (0x8B 0xE4 0xC3)'),
    ]
    for pattern, desc in stack_pivot_patterns:
        if re.search(pattern, binary_data):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'STACK_PIVOT_GADGET',
                'detail': (
                    f'Stack pivot gadget detected: {desc} — this sequence transfers stack '
                    'control to an attacker-chosen address by swapping or overwriting ESP; '
                    'the pivot is the first gadget in most ROP chains: DEP blocks injected '
                    'shellcode execution, so the pivot points ESP at a fake stack containing '
                    'gadget addresses, and subsequent RETNs consume attacker-controlled values '
                    'from that fake stack; INT 2D-based anti-debugging (PMA ch16) similarly '
                    'manipulates the stack pointer to disrupt single-step exception handling '
                    '(PMA ch9: OllyDbg stack view during RETN; '
                    'ch16: exception-based control flow and ICE breakpoint stack effects)'
                ),
                'host': 'localhost',
                'port': 0,
            })
            break

    # VirtualProtect with RETN bytes between occurrences — ROP-chained DEP bypass
    # Each gadget sets one argument register then RETNs; final RETN enters now-executable region
    vp_positions = [m.start() for m in re.finditer(rb'VirtualProtect', binary_data)]
    if len(vp_positions) >= 2:
        for i in range(len(vp_positions) - 1):
            gap = binary_data[vp_positions[i]:vp_positions[i + 1]]
            if b'\xc3' in gap:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'ROP_VIRTUALPROTECT',
                    'detail': (
                        '"VirtualProtect" appears at multiple offsets with RETN (0xC3) bytes '
                        'between occurrences — pattern matches a ROP chain that calls '
                        'VirtualProtect across multiple gadgets to defeat DEP; each gadget '
                        'positions one argument (lpAddress, dwSize, flNewProtect, lpflOldProtect) '
                        'and RETNs to the next; the terminal RETN transfers to the now-executable '
                        'shellcode region; discontiguous VirtualProtect references with intervening '
                        'RETs distinguish ROP dispatch from a single direct call '
                        '(PMA ch19: DEP bypass via existing code reuse; '
                        'appendix A: VirtualProtect — "change protection on region of pages")'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
                break

    # VirtualProtect + PUSH 0x40 (PAGE_EXECUTE_READWRITE) — explicit DEP page flip
    # flNewProtect argument 0x40 marks a region executable+writable, defeating NX/DEP
    if vp_positions:
        for pos in vp_positions:
            window_start = max(0, pos - 128)
            window_end = min(len(binary_data), pos + 128)
            window = binary_data[window_start:window_end]
            # PUSH imm8 0x40: 0x6A 0x40; PUSH imm32 0x00000040: 0x68 0x40 0x00 0x00 0x00
            if b'\x6a\x40' in window or b'\x68\x40\x00\x00\x00' in window:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'DEP_BYPASS_VIRTUALPROTECT',
                    'detail': (
                        '"VirtualProtect" called with PAGE_EXECUTE_READWRITE (0x40) as '
                        'an immediate PUSH argument — binary explicitly marks a memory '
                        'region as executable+writable, defeating Data Execution Prevention; '
                        'PUSH 0x40 (0x6A 0x40) adjacent to VirtualProtect confirms '
                        'flNewProtect=0x40, not incidental data; technique used both in '
                        'direct shellcode loaders and as the terminal ROP gadget sequence '
                        'that unlocks the payload region before jumping into it; '
                        'OllyDbg memory map (Alt+M) shows the protection change take effect '
                        '(PMA ch19: shellcode loading; '
                        'appendix A: VirtualProtect PAGE_EXECUTE_READWRITE)'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
                break

    return findings


def detect_anti_disassembly_techniques(binary_data: bytes) -> list:
    """Detect anti-disassembly patterns in binary data.

    Sourced from: Practical Malware Analysis ch15 (Anti-Disassembly — constant-condition
    jumps, impossible disassembly, inward-pointing JMPs) and ch16 (Obscuring Flow Control
    — return-pointer abuse, SEH-based covert dispatch).
    These techniques exploit disassembler assumptions: linear sweep decodes the byte
    immediately following a conditional jump even when that path is never taken, and
    cannot represent a single byte as part of two simultaneous instructions.

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    def _finding(severity, title, detail):
        return {'severity': severity, 'title': title, 'detail': detail,
                'host': 'localhost', 'port': 0}

    # --- Constant condition jumps ---
    # JZ (0x74) immediately followed by JNZ (0x75) with any relative offset, or vice versa:
    # the pair acts as an unconditional JMP but the disassembler processes the false branch.
    # Also: XOR reg,reg (zeroes register, sets ZF) immediately before JZ/JNZ — branch
    # outcome is predetermined. PMA ch15: "jump instructions with same target" and
    # "jump with constant condition" (xor eax,eax; jz — figs 15-2, 15-3).
    const_jmp = False
    if re.search(b'\x74.\x75', binary_data) or re.search(b'\x75.\x74', binary_data):
        const_jmp = True
    # XOR reg,reg ModRM bytes for same-register: C0=EAX, C9=ECX, D2=EDX, DB=EBX,
    # E4=ESP, ED=EBP, F6=ESI, FF=EDI (opcode 31 or 33, mod=11, reg==rm)
    if re.search(b'[\x31\x33][\xc0\xc9\xd2\xdb\xe4\xed\xf6\xff][\x74\x75]', binary_data):
        const_jmp = True
    if const_jmp:
        findings.append(_finding(
            'MEDIUM',
            'ANTI_DISASSEMBLY_CONST_JMP',
            (
                'Constant condition jump detected — JZ/JNZ pair (74/75) targeting the '
                'same effective address (always-taken unconditional disguised as conditional), '
                'or XOR reg,reg (31/33 + same-register ModRM) immediately before JZ/JNZ '
                'making the branch outcome predetermined; disassembler recursing into the '
                'false path decodes a rogue byte (typically 0xE8 CALL or 0xE9 JMP opcode) '
                'as a 5-byte instruction, hiding the 4 real bytes that follow the true '
                'target; red cross-references in IDA Pro (reference inside existing '
                'instruction, not at its start) are the first indicator; fix: press D on '
                'the rogue byte to mark as data, C on the real target byte to re-disassemble '
                '(PMA ch15: JZ+JNZ same-target fig 15-2; XOR+JZ constant-condition fig 15-3)'
            ),
        ))

    # --- Jump into middle of instruction (impossible disassembly) ---
    # Short JMP (EB) with a negative offset placing the target inside the JMP opcode
    # itself, or CALL $+5 (E8 00 00 00 00) — a self-referential call that leaves a
    # return pointer on the stack for arithmetic to build a PIC pointer to hidden code.
    # PMA ch15: "impossible disassembly" figs 15-4/15-5 — processor executes the
    # inward-pointing byte as part of a second instruction; no disassembler can represent
    # one byte as belonging to two simultaneous instructions.
    jump_split = False
    # EB FF = JMP short -1: target = ip+2+(-1) = ip+1 (own second byte)
    # EB FE = JMP short -2: target = ip+2+(-2) = ip (own first byte) — tight-loop disguise
    if b'\xeb\xff' in binary_data or b'\xeb\xfe' in binary_data:
        jump_split = True
    # CALL $+5: E8 00 00 00 00 — call falls through to next byte, pushing return address
    # for subsequent ADD [ESP], offset to construct a pointer to hidden code (ch16, ch19)
    if b'\xe8\x00\x00\x00\x00' in binary_data:
        jump_split = True
    # Short JMP with small negative offset (EB F8..EB FD): target in [-8..-3] from start
    # likely lands inside a preceding multi-byte instruction
    for m in re.finditer(b'\xeb([\xf8-\xfd])', binary_data):
        signed_off = m.group(1)[0] - 256
        target = m.start() + 2 + signed_off
        if 0 <= target < m.start() + 2:
            jump_split = True
            break
    if jump_split:
        findings.append(_finding(
            'HIGH',
            'ANTI_DISASSEMBLY_JUMP_SPLIT',
            (
                'Jump to middle of instruction detected — EB FF (short JMP offset -1 '
                'lands on own second byte), EB FE (tight-loop JMP -2 to own first byte), '
                'EB F8..FD (negative short JMP into preceding instruction bytes), or '
                'E8 00 00 00 00 (CALL $+5 self-referential: pushes return address then '
                'ADD [ESP],N redirects to hidden code N bytes ahead); the processor '
                'executes the inward-pointing byte as both part of the outer instruction '
                'and the start of an inner instruction; no linear-sweep or recursive '
                'disassembler can represent this — one path produces an invalid listing, '
                'the other hides the second execution; IDA Pro shows the conflict as a '
                'red cross-reference pointing inside an existing instruction; fix: '
                'IDAPython NopBytes() over the impossible region then C on real target '
                '(PMA ch15: "impossible disassembly" figs 15-4/15-5; multilevel inward- '
                'jumping fig 15-5; ch16: CALL $+5 return-pointer abuse)'
            ),
        ))

    # --- SEH-based flow obfuscation ---
    # Structured Exception Handling misused as a covert GOTO: attacker builds an
    # EXCEPTION_REGISTRATION record on the stack (push handler; push fs:[0];
    # mov fs:[0],esp), triggers a hardware exception (div-by-zero, invalid access),
    # OS dispatches to the handler — a subroutine with no static call/JMP reference.
    # Disassembler sees no cross-reference to the handler and may not disassemble it.
    # PMA ch16: "Misusing Structured Exception Handlers" — push/div-by-zero example.
    seh_flow = False
    # push dword ptr fs:[0]: 64 FF 35 00 00 00 00 (FS override + PUSH [imm32=0])
    if b'\x64\xff\x35\x00\x00\x00\x00' in binary_data:
        seh_flow = True
    # mov dword ptr fs:[0], esp: 64 89 25 00 00 00 00
    if b'\x64\x89\x25\x00\x00\x00\x00' in binary_data:
        seh_flow = True
    # mov eax, dword ptr fs:[0]: 64 A1 00 00 00 00 (reading SEH chain head to unlink)
    if b'\x64\xa1\x00\x00\x00\x00' in binary_data:
        seh_flow = True
    # XOR ECX,ECX + DIV ECX: 31/33 C9 F7 F1 — divide-by-zero exception trigger (ch16)
    # also XOR EDX,EDX + DIV EDX: 31/33 D2 F7 F2
    if re.search(b'[\x31\x33][\xc9\xd2]\xf7[\xf1\xf2]', binary_data):
        seh_flow = True
    # SEH API string markers (two or more confirms SEH usage pattern)
    _seh_apis = [b'RaiseException', b'SetUnhandledExceptionFilter',
                 b'AddVectoredExceptionHandler', b'RtlUnwind']
    _seh_hits = sum(1 for api in _seh_apis if api in binary_data)
    if _seh_hits >= 2 or (_seh_hits >= 1 and seh_flow):
        seh_flow = True
    if seh_flow:
        findings.append(_finding(
            'HIGH',
            'ANTI_DISASSEMBLY_SEH_FLOW',
            (
                'SEH exception handler used for covert control flow — fs:[0] manipulation '
                'bytes detected (64 FF 35 push-SEH-head, 64 89 25 write-SEH-head, or '
                '64 A1 read-SEH-head), or divide-by-zero exception trigger sequence '
                '(XOR ECX/EDX,ECX/EDX then DIV ECX/EDX: 31/33 C9/D2 F7 F1/F2), or '
                'multiple SEH API imports (RaiseException, SetUnhandledExceptionFilter, '
                'AddVectoredExceptionHandler, RtlUnwind); attacker installs a handler '
                'with push handler / push fs:[0] / mov fs:[0],esp, triggers an exception '
                '(div-by-zero or memory fault), OS dispatches to handler — a subroutine '
                'with zero disassembler cross-references; handler unlinks itself via '
                'mov esp,[esp+8] / fs:[0] chain traversal before executing payload; '
                'IDA Pro does not auto-follow SEH dispatch — handler code appears as '
                'orphaned data until analyst presses C; Software DEP/SafeSEH bypass '
                'requires /SAFESEH:NO or handwritten-assembly SafeSEH directive '
                '(PMA ch16: "Misusing Structured Exception Handlers" push/div-zero '
                'example at 00401050; EXCEPTION_REGISTRATION struct; fs:0 chain)'
            ),
        ))

    # --- Self-modifying code ---
    # WriteProcessMemory targeting the binary's own code section + FlushInstructionCache
    # invalidates the CPU instruction cache after the write, confirming the modification
    # is intended to execute. GetCurrentProcess as the hProcess argument (pseudo-handle
    # 0xFFFFFFFF) is the self-targeting indicator.
    # PMA ch15: extreme impossible disassembly — static analysis of patched bytes is
    # invalid before execution; ch18: packer stubs use this pattern to write unpacked
    # image then redirect to original entry point (OEP).
    self_modify = False
    if b'WriteProcessMemory' in binary_data and b'FlushInstructionCache' in binary_data:
        self_modify = True
    if b'WriteProcessMemory' in binary_data and b'GetCurrentProcess' in binary_data:
        self_modify = True
    if b'NtWriteVirtualMemory' in binary_data and b'NtProtectVirtualMemory' in binary_data:
        self_modify = True
    if self_modify:
        findings.append(_finding(
            'HIGH',
            'ANTI_DISASSEMBLY_SELF_MODIFY',
            (
                'Self-modifying code indicators detected — WriteProcessMemory combined '
                'with FlushInstructionCache (the definitive SMC pair: write then '
                'invalidate CPU instruction cache to force re-fetch of patched bytes), '
                'or WriteProcessMemory + GetCurrentProcess (pseudo-handle 0xFFFFFFFF '
                'as hProcess = self-targeting), or NtWriteVirtualMemory + '
                'NtProtectVirtualMemory native-API pair (kernel-level SMC path bypassing '
                'Win32 layer); the binary patches its own .text section at runtime so '
                'static disassembly of the modified region is invalid until execution '
                'reaches and applies the patch; packers apply this to write the '
                'decompressed image and redirect EIP to OEP; mid-execution SMC mutates '
                'functions between calls to defeat static signatures and cached analysis; '
                'OllyDbg memory-write breakpoint on the code region surfaces the write '
                'event (PMA ch15: self-modification as extreme impossible disassembly; '
                'ch18: packer OEP redirect via self-write; appendix A: '
                'WriteProcessMemory / FlushInstructionCache signatures)'
            ),
        ))

    return findings


def detect_junk_code_insertion(binary_data: bytes) -> list:
    """Detect junk code insertion and opaque predicate obfuscation patterns.

    Sourced from: Practical Malware Analysis ch15 (Anti-Disassembly — NOP-out
    technique, rogue bytes, opaque predicate xor/jz construct), ch16 (Obscuring
    Flow Control — dead branches after unconditional transfers), and ch18
    (Packers and Unpacking — NOP sleds in shellcode loaders, dead regions).

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    def _finding(severity, title, detail):
        return {'severity': severity, 'title': title, 'detail': detail,
                'host': 'localhost', 'port': 0}

    # --- NOP sled density ---
    # More than 16 consecutive 0x90 (NOP) bytes outside the PE header region.
    # PE headers occupy the first ~0x400 bytes; NOP runs there are section-alignment
    # padding. Beyond that threshold, dense NOP runs are used to absorb imprecise jump
    # landings (shellcode sled) or to create disassembler interference by padding between
    # real instruction sequences, forcing the linear sweep to consume uniform bytes.
    # PMA ch15: IDAPython NOP-out script (PatchByte to 0x90) — attacker co-opts the same
    # opcode; ch19: NOP sleds as shellcode landing-zone preamble for imprecise delivery.
    PE_HEADER_SKIP = 0x400
    NOP_RUN_MIN = 17  # >16 consecutive NOPs = anomalous
    search_region = binary_data[PE_HEADER_SKIP:] if len(binary_data) > PE_HEADER_SKIP else binary_data
    nop_re = re.compile(b'\x90{' + str(NOP_RUN_MIN).encode() + b',}')
    nop_match = nop_re.search(search_region)
    if nop_match:
        longest_run = max(len(m.group()) for m in nop_re.finditer(search_region))
        findings.append(_finding(
            'MEDIUM',
            'JUNK_CODE_NOP_SLED',
            (
                f'NOP sled detected outside PE header region (>{PE_HEADER_SKIP:#x} offset) '
                f'— longest consecutive run: {longest_run} x 0x90 bytes '
                f'(threshold: {NOP_RUN_MIN - 1}); '
                'dense NOP padding beyond alignment needs indicates shellcode landing-zone '
                'construction (absorbs imprecise jump target offset variation) or deliberate '
                'disassembler interference (forces linear-sweep to consume a uniform block '
                'and lose the instruction boundary that follows); IDA Pro NOP-out technique '
                '(IDAPython PatchByte to 0x90 then MakeCode) uses the same byte to '
                'sanitise impossible-disassembly regions — attacker co-opts the opcode '
                'to blend junk into a plausible sled; inspect bytes immediately after '
                'the sled for the real payload entry point '
                '(PMA ch15: IDAPython NopBytes() technique; ch19: NOP sled as shellcode '
                'landing-zone preamble for imprecise exploit delivery)'
            ),
        ))

    # --- Dead code blocks after unconditional transfer ---
    # Non-zero, non-NOP, non-INT3 bytes immediately following RET (0xC3) or a short
    # unconditional JMP (0xEB XX, forward offset) that are never executed but are decoded
    # by the disassembler's linear-sweep pass, producing conflicting instruction listings.
    # This is the "rogue byte" technique from PMA ch15 — a byte placed after a conditional
    # jump causes the disassembler to decode a multi-byte false instruction that hides the
    # real instruction beginning at rogue_byte+1 or the JMP true target.
    dead_block = False
    _skip_bytes = {0x00, 0x90, 0xCC, 0xC3, 0xCD}  # null, NOP, INT3, RET, INT nn
    # RET (C3) followed by non-padding byte
    for m in re.finditer(b'\xc3(.)', binary_data, re.DOTALL):
        if m.group(1)[0] not in _skip_bytes:
            dead_block = True
            break
    # Short forward JMP (EB XX with XX in [01..FD]) followed by non-padding byte
    # at the instruction's exit point (the byte immediately after the 2-byte instruction)
    if not dead_block:
        for m in re.finditer(b'\xeb[\x01-\xfd](.)', binary_data, re.DOTALL):
            if m.group(1)[0] not in _skip_bytes:
                dead_block = True
                break
    if dead_block:
        findings.append(_finding(
            'MEDIUM',
            'JUNK_CODE_DEAD_BLOCK',
            (
                'Dead code block detected — non-zero, non-NOP, non-INT3 bytes immediately '
                'follow an unconditional control transfer (RET 0xC3 or short JMP 0xEB); '
                'these bytes are unreachable at runtime but the disassembler\'s '
                'linear-sweep pass decodes them as instructions, producing an overlapping '
                'or conflicting listing with the true execution path at the JMP target; '
                'the technique is most effective when the rogue byte is the opcode of a '
                'multi-byte instruction (0xE8 CALL, 0xE9 JMP, 0x66 operand-size prefix) '
                'so the 4 bytes after it are consumed as operands, hiding real instructions; '
                'combined with constant-condition jumps, the disassembler trusts the '
                'dead false-branch over the taken true-branch because it processes '
                'sequential bytes first; fix in IDA Pro: D key on rogue byte (mark as '
                'data), C key on the first real instruction after the dead region '
                '(PMA ch15: "rogue byte" technique; ch16: disassembler false-branch '
                'trust after unconditional control transfer)'
            ),
        ))

    # --- Opaque predicates ---
    # An arithmetic expression whose result is always determined (ZF always set or
    # always clear) is used as a branch condition, making the branch appear conditional
    # to static analysis but deterministic at runtime.
    # PMA ch15: XOR EAX,EAX + JZ is the canonical opaque predicate — ZF=1 guaranteed,
    # branch always taken; the false (JNZ) path receives full disassembly and populates
    # the control-flow graph with dead nodes. Automated obfuscation tools insert these
    # at every basic-block boundary in heavily obfuscated packers.
    opaque = False
    # XOR reg,reg → JZ/JNZ: 31/33 + same-register ModRM + 74/75
    # ZF=1 guaranteed; JZ always branches (NOP predicate), JNZ never branches (dead path)
    # ModRM same-register bytes: C0=EAX,EAX C9=ECX,ECX D2=EDX,EDX DB=EBX,EBX
    #                             E4=ESP,ESP ED=EBP,EBP F6=ESI,ESI FF=EDI,EDI
    if re.search(b'[\x31\x33][\xc0\xc9\xd2\xdb\xe4\xed\xf6\xff][\x74\x75]', binary_data):
        opaque = True
    # AND reg, imm8=0 → JZ/JNZ: 83 /4 (AND) rm=reg8 00 74/75
    # E0=AND EAX,0 E1=AND ECX,0 E2=AND EDX,0 E3=AND EBX,0
    # E4=AND ESP,0 E5=AND EBP,0 E6=AND ESI,0 E7=AND EDI,0
    if re.search(b'\x83[\xe0-\xe7]\x00[\x74\x75]', binary_data):
        opaque = True
    # SUB reg,reg → JZ/JNZ: 29/2B + same-register ModRM + 74/75
    # subtraction of register from itself = 0, ZF always set
    if re.search(b'[\x29\x2b][\xc0\xc9\xd2\xdb\xe4\xed\xf6\xff][\x74\x75]', binary_data):
        opaque = True
    if opaque:
        findings.append(_finding(
            'MEDIUM',
            'JUNK_CODE_OPAQUE_PREDICATE',
            (
                'Opaque predicate detected — XOR reg,reg (31/33 + same-register ModRM) '
                'or AND reg,0 (83 E0-E7 00) or SUB reg,reg (29/2B + same-register ModRM) '
                'immediately preceding a conditional branch (JZ 0x74 or JNZ 0x75); '
                'the arithmetic outcome is predetermined (ZF always set by XOR/SUB '
                'self-operation or AND with zero immediate) so the branch direction is '
                'fixed at every execution but appears to the disassembler and analyst as '
                'a genuine runtime decision; the never-taken path receives full disassembly '
                'and populates the control-flow graph with dead basic blocks, inflating '
                'complexity; automated obfuscation tools insert opaque predicates at '
                'every basic-block boundary to maximise CFG pollution; fix in IDA Pro: '
                'identify the ZF-setting instruction, press D on the dead-path byte, C '
                'on the real successor; IDAPython batch-NOP dead branches at scale '
                '(PMA ch15: XOR EAX,EAX + JZ canonical opaque predicate; '
                '"false conditional of xor followed by jz" fig 15-3)'
            ),
        ))

    return findings


def detect_sandbox_environment_indicators() -> list:
    """Detect analysis/sandbox environment indicators on the local system.

    Evasive malware enumerates these artifacts to decide whether to execute.
    Synthesized from: Evasive Malware ch4 (OS artifact enumeration — VM flags,
    DMI product names, analysis tool processes) and ch6 (hardware enumeration —
    CPU count, RAM allotment as sandbox discriminators).

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings = []

    if not os.path.isdir('/proc'):
        return [_not_linux_finding('detect_sandbox_environment_indicators')]

    # /proc/cpuinfo: hypervisor flag and VM CPU identity strings
    try:
        with open('/proc/cpuinfo', 'r', errors='replace') as f:
            cpuinfo = f.read()
        for line in cpuinfo.splitlines():
            if line.startswith('flags') and 'hypervisor' in line:
                findings.append(_make_finding(
                    'HIGH',
                    'HYPERVISOR_FLAG_DETECTED',
                    '/proc/cpuinfo flags field contains "hypervisor" — CPU reports '
                    'virtualization via CPUID bit; evasive malware reads this bit '
                    '(CPUID leaf 1 ECX bit 31) to detect VM/sandbox and abort execution',
                ))
                break
        _vm_cpu_pat = re.compile(r'(QEMU|VirtualBox|VMware|KVM|Bochs|Microsoft Hv)', re.IGNORECASE)
        for line in cpuinfo.splitlines():
            if line.startswith('vendor_id') or line.startswith('model name'):
                m = _vm_cpu_pat.search(line)
                if m:
                    findings.append(_make_finding(
                        'HIGH',
                        'HYPERVISOR_FLAG_DETECTED',
                        f'/proc/cpuinfo reports VM CPU identity "{m.group()}" in '
                        f'"{line.strip()}" — hypervisor emulation exposed in processor '
                        'identification strings; checked by malware via CPUID vendor leaf',
                    ))
                    break
    except OSError:
        pass

    # DMI/SMBIOS: product_name and sys_vendor expose VM platform identity
    _VM_ID_STRINGS = (
        'VirtualBox', 'VMware', 'QEMU', 'KVM', 'Hyper-V',
        'Microsoft Corporation', 'Bochs', 'Parallels', 'Xen', 'innotek',
    )
    for dmi_path, title in (
        ('/sys/class/dmi/id/product_name', 'VM_PRODUCT_NAME'),
        ('/sys/class/dmi/id/sys_vendor',   'VM_VENDOR_DETECTED'),
        ('/sys/class/dmi/id/board_vendor', 'VM_VENDOR_DETECTED'),
    ):
        try:
            with open(dmi_path, 'r', errors='replace') as f:
                val = f.read().strip()
            for vs in _VM_ID_STRINGS:
                if vs.lower() in val.lower():
                    findings.append(_make_finding(
                        'HIGH',
                        title,
                        f'{dmi_path}: "{val}" matches VM identifier "{vs}" — '
                        'SMBIOS/DMI tables expose virtualization platform; malware '
                        'reads these via /sys/class/dmi/id/ or WMI Win32_ComputerSystem',
                    ))
                    break
        except OSError:
            pass

    # Analysis tool processes: scan /proc/*/cmdline for known tool names
    _ANALYSIS_TOOLS = frozenset({
        'wireshark', 'tcpdump', 'strace', 'ltrace', 'gdb', 'radare2',
        'ida', 'ghidra', 'x64dbg', 'ollydbg', 'pestudio', 'procmon',
        'procexp', 'autoruns', 'fiddler', 'frida', 'cuckoo', 'anyrun',
    })
    try:
        for entry in os.scandir('/proc'):
            if not entry.is_dir() or not entry.name.isdigit():
                continue
            try:
                with open(f'/proc/{entry.name}/cmdline', 'rb') as f:
                    cmdline = f.read().decode('utf-8', errors='replace').lower()
                for tool in _ANALYSIS_TOOLS:
                    if tool in cmdline:
                        findings.append(_make_finding(
                            'HIGH',
                            'ANALYSIS_TOOL_PROCESS',
                            f'PID {entry.name}: analysis/debugging tool "{tool}" detected '
                            f'in cmdline: {cmdline[:80].strip()} — evasive malware '
                            'enumerates running processes to detect analyst tooling',
                        ))
                        break
            except OSError:
                pass
    except OSError:
        pass

    # VMware guest tools filesystem artifacts
    for vmw_path in (
        '/usr/bin/vmtoolsd', '/usr/bin/vmware-toolbox',
        '/etc/vmware-tools', '/usr/lib/vmware-tools',
    ):
        if os.path.exists(vmw_path):
            findings.append(_make_finding(
                'HIGH',
                'VMWARE_GUEST_TOOLS',
                f'{vmw_path} exists — VMware Guest Tools installed; confirms VMware '
                'virtualization environment; malware checks for this path and '
                'vmtoolsd process presence as a VM discriminator',
            ))
            break

    # VirtualBox guest additions filesystem artifacts
    for vbox_path in (
        '/usr/bin/VBoxService', '/usr/sbin/VBoxService',
        '/usr/bin/VBoxClient', '/lib/virtualbox',
    ):
        if os.path.exists(vbox_path):
            findings.append(_make_finding(
                'HIGH',
                'VIRTUALBOX_GUEST_ADDITIONS',
                f'{vbox_path} exists — VirtualBox Guest Additions installed; confirms '
                'VirtualBox VM; malware checks VBoxService process and this path as '
                'a reliable VBox discriminator',
            ))
            break

    # CPU count: VMs commonly configured with 1-2 CPUs
    cpu_count = os.cpu_count() or 0
    if cpu_count < 2:
        findings.append(_make_finding(
            'MEDIUM',
            'LOW_CPU_COUNT',
            f'os.cpu_count()={cpu_count} — fewer than 2 logical CPUs detected; '
            'automated sandboxes minimise host overhead by allocating 1 CPU; '
            'real workstations typically have 4+ cores; checked by malware via '
            'GetSystemInfo/sysconf(_SC_NPROCESSORS_ONLN)',
        ))

    # Memory: /proc/meminfo MemTotal < 1 GiB
    try:
        with open('/proc/meminfo', 'r', errors='replace') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    mem_kb = int(line.split()[1])
                    if mem_kb < 1024 * 1024:  # < 1 GiB
                        findings.append(_make_finding(
                            'MEDIUM',
                            'LOW_MEMORY_SANDBOX',
                            f'/proc/meminfo MemTotal={mem_kb}kB '
                            f'({mem_kb // 1024}MB) < 1GiB — low RAM allocation '
                            'characteristic of automated sandbox VMs; real systems '
                            'typically have 4GB+; malware checks via GlobalMemoryStatusEx',
                        ))
                    break
    except OSError:
        pass

    # Uptime: /proc/uptime — sandboxes boot fresh per sample
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_sec = float(f.read().split()[0])
        if uptime_sec < 120.0:
            findings.append(_make_finding(
                'HIGH',
                'LOW_UPTIME_FRESHLY_BOOTED',
                f'/proc/uptime={uptime_sec:.1f}s — system up less than 120 seconds; '
                'automated sandboxes boot a fresh VM per detonation and run the sample '
                'within seconds of boot; real user machines have multi-hour uptimes',
            ))
    except OSError:
        pass

    # User activity artifacts: empty bash_history and Downloads dirs
    no_activity = []
    try:
        for home_entry in os.scandir('/home'):
            if not home_entry.is_dir():
                continue
            hist_path = os.path.join(home_entry.path, '.bash_history')
            try:
                if os.path.getsize(hist_path) == 0:
                    no_activity.append(f'{hist_path} (empty)')
            except OSError:
                no_activity.append(f'{hist_path} (missing)')
            dl_path = os.path.join(home_entry.path, 'Downloads')
            try:
                if os.path.isdir(dl_path) and not os.listdir(dl_path):
                    no_activity.append(f'{dl_path} (empty dir)')
            except OSError:
                pass
    except OSError:
        pass
    try:
        if os.path.getsize('/root/.bash_history') == 0:
            no_activity.append('/root/.bash_history (empty)')
    except OSError:
        pass
    if no_activity:
        findings.append(_make_finding(
            'HIGH',
            'NO_USER_ACTIVITY_ARTIFACTS',
            'Empty/missing user activity artifacts: ' + ', '.join(no_activity[:6]) +
            ' — real user environments accumulate shell history and downloads; '
            'absence indicates freshly provisioned sandbox or lab VM; malware '
            'checks these paths as human-interaction discriminators',
        ))

    return findings


def detect_process_injection_surface() -> list:
    """Detect process injection vectors and attack surface on the live system.

    Synthesized from: Evasive Malware ch4 (OS artifact enumeration — ptrace,
    core_pattern abuse, /proc/mem access) and Practical Binary Analysis ch05
    (binary instrumentation, ptrace-based DBI/injection mechanics).

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings = []

    if not os.path.isdir('/proc'):
        return [_not_linux_finding('detect_process_injection_surface')]

    # ptrace_scope=0: any process can ptrace any other same-uid process
    try:
        with open('/proc/sys/kernel/yama/ptrace_scope', 'r') as f:
            scope = f.read().strip()
        if scope == '0':
            findings.append(_make_finding(
                'HIGH',
                'PTRACE_UNRESTRICTED',
                '/proc/sys/kernel/yama/ptrace_scope=0 — any process can attach to '
                'any other process owned by the same uid via ptrace; enables classical '
                'injection (PTRACE_ATTACH -> PTRACE_POKEDATA/PTRACE_SETREGS) without '
                'elevated privilege; harden to 1 (parent-only) or higher',
            ))
    except OSError:
        pass

    # core_pattern pipe prefix: kernel execs the handler as root on crash
    try:
        with open('/proc/sys/kernel/core_pattern', 'r') as f:
            core_pat = f.read().strip()
        if core_pat.startswith('|'):
            findings.append(_make_finding(
                'HIGH',
                'CORE_DUMP_PIPE_ESCALATION',
                f'/proc/sys/kernel/core_pattern="{core_pat}" — pipe prefix causes the '
                'kernel to exec the handler program as root with the core on stdin; '
                'if the handler path is world-writable, a crash triggers privilege '
                'escalation; also used by container escapes (e.g., CVE-2019-5736)',
            ))
    except OSError:
        pass

    # /dev/shm: large anonymous shared memory segments used to stage payloads
    if os.path.isdir('/dev/shm'):
        try:
            for entry in os.scandir('/dev/shm'):
                try:
                    seg_size = entry.stat().st_size
                    if seg_size > 10 * 1024 * 1024:  # > 10 MiB
                        findings.append(_make_finding(
                            'MEDIUM',
                            'LARGE_SHARED_MEMORY_SEGMENT',
                            f'/dev/shm/{entry.name}: {seg_size // (1024 * 1024)}MiB — '
                            'large anonymous shared memory segment; injection techniques '
                            'stage shellcode here for execution by a cooperating process '
                            'or across container namespace boundaries',
                        ))
                except OSError:
                    pass
        except OSError:
            pass

    # Per-process scan: rwx memory regions and LD_PRELOAD
    rwx_by_pid = {}    # pid -> list of (addr_range, pathname)
    ld_preload_hits = []  # list of (pid, value)

    try:
        for entry in os.scandir('/proc'):
            if not entry.is_dir() or not entry.name.isdigit():
                continue
            pid = entry.name

            # /proc/<pid>/maps: collect rwx regions
            try:
                with open(f'/proc/{pid}/maps', 'r', errors='replace') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                        perms = parts[1]
                        if 'r' in perms and 'w' in perms and 'x' in perms:
                            addr_range = parts[0]
                            pathname = ' '.join(parts[5:]) if len(parts) > 5 else ''
                            rwx_by_pid.setdefault(pid, []).append((addr_range, pathname))
            except OSError:
                pass

            # /proc/<pid>/environ: LD_PRELOAD set in process environment
            try:
                with open(f'/proc/{pid}/environ', 'rb') as f:
                    raw_env = f.read().decode('utf-8', errors='replace')
                for item in raw_env.split('\x00'):
                    if item.startswith('LD_PRELOAD='):
                        ld_preload_hits.append((pid, item[len('LD_PRELOAD='):]))
                        break
            except OSError:
                pass

    except OSError:
        pass

    # Emit findings for rwx regions
    for pid, regions in rwx_by_pid.items():
        first_addr, first_path = regions[0]
        findings.append(_make_finding(
            'CRITICAL',
            'PROCESS_RWX_MEMORY_REGION',
            f'PID {pid}: {len(regions)} rwx (read+write+execute) memory region(s); '
            f'first: {first_addr} path={first_path!r} — simultaneous w+x enables '
            'shellcode staging and in-place execution; classic injection indicator',
        ))
        if len(regions) > 1:
            # Multiple rwx maps indicate active injection or heavily instrumented process
            all_addrs = ', '.join(r[0] for r in regions[:4])
            findings.append(_make_finding(
                'CRITICAL',
                'LIVE_PROCESS_RWX_MAP',
                f'PID {pid}: {len(regions)} rwx maps ({all_addrs}{"..." if len(regions) > 4 else ""}) '
                '— multiple simultaneous writable+executable sections; normal ASLR PIE '
                'binaries produce 0; count >1 indicates injected shellcode, DBI framework, '
                'or unpacked payload executing from heap/anonymous regions',
            ))

    # Emit findings for LD_PRELOAD active processes
    for pid, val in ld_preload_hits:
        findings.append(_make_finding(
            'CRITICAL',
            'LD_PRELOAD_ACTIVE_PROCESS',
            f'PID {pid}: LD_PRELOAD={val!r} active in process environment — '
            'preloaded library intercepts all subsequent dynamic linker resolutions; '
            'rootkit technique to hook libc functions (read, write, open, connect) '
            'and redirect execution; see also /etc/ld.so.preload for system-wide hook',
        ))

    # /proc/<pid>/mem write access for cross-uid processes
    my_uid = os.getuid()
    try:
        for entry in os.scandir('/proc'):
            if not entry.is_dir() or not entry.name.isdigit():
                continue
            pid = entry.name
            try:
                proc_uid = None
                with open(f'/proc/{pid}/status', 'r') as f:
                    for line in f:
                        if line.startswith('Uid:'):
                            proc_uid = int(line.split()[1])
                            break
                if proc_uid is not None and proc_uid != my_uid:
                    mem_path = f'/proc/{pid}/mem'
                    if os.access(mem_path, os.W_OK):
                        findings.append(_make_finding(
                            'HIGH',
                            'PROC_MEM_WRITE_ACCESS',
                            f'/proc/{pid}/mem writable by uid={my_uid} for process '
                            f'owned by uid={proc_uid} — cross-uid /proc/mem write '
                            'enables direct memory injection without ptrace; '
                            'requires kernel ptrace_scope bypass or CAP_SYS_PTRACE',
                        ))
            except OSError:
                pass
    except OSError:
        pass

    return findings


def detect_bash_history_artifacts() -> list:
    """Detect bash history artifacts indicating offensive tool usage or privilege escalation.

    Scans /home/*/.bash_history and /root/.bash_history for patterns associated with
    reverse shells, privilege escalation, data exfiltration, password cracking,
    network scanning, track-clearing, crontab modification, and persistence techniques
    as documented in Black Hat Bash chapters 8 (local info gathering), 9 (privilege
    escalation), 10 (persistence), and 12 (defense evasion and exfiltration).

    Returns List[dict]: each dict has {severity, title, detail, host, port}.
    """
    import glob

    findings = []

    # Patterns: (category_key, severity, title, compiled_pattern_list)
    categories = [
        (
            'reverse_shell',
            'HIGH',
            'BASH_HISTORY_REVERSE_SHELL',
            [
                re.compile(r'nc\s+.*-e\s', re.IGNORECASE),
                re.compile(r'bash\s+-i\s+>&?\s*/dev/tcp/', re.IGNORECASE),
                re.compile(r'python[23]?\s+-c\s+["\']import\s+socket', re.IGNORECASE),
                re.compile(r'/dev/tcp/', re.IGNORECASE),
                re.compile(r'mkfifo\s+.*&&.*nc\s', re.IGNORECASE),
                re.compile(r'rm\s+/tmp/[a-z]+;mkfifo', re.IGNORECASE),
                re.compile(r'ncat\s+.*--sh-exec', re.IGNORECASE),
            ],
        ),
        (
            'privesc',
            'HIGH',
            'BASH_HISTORY_PRIVESC_ATTEMPT',
            [
                re.compile(r'sudo\s+(su|bash|sh)\b', re.IGNORECASE),
                re.compile(r'\bpkexec\b', re.IGNORECASE),
                re.compile(r'gdb\s+-p\s+\d+', re.IGNORECASE),
                re.compile(r'python[23]?\s+-c\s+["\']import\s+os.*os\.setuid', re.IGNORECASE),
                re.compile(r'chmod\s+[u+]*s\s+', re.IGNORECASE),
                re.compile(r'sudo\s+-l\b', re.IGNORECASE),
                re.compile(r'\bLD_PRELOAD\s*=', re.IGNORECASE),
                re.compile(r'\bdirtyc0w\b|\bdirtycow\b', re.IGNORECASE),
            ],
        ),
        (
            'data_exfil',
            'CRITICAL',
            'BASH_HISTORY_DATA_EXFIL',
            [
                re.compile(r'curl\s+.*-d\s+@/etc/(shadow|passwd|sudoers)', re.IGNORECASE),
                re.compile(r'wget\s+.*--post-file\s*=\s*/etc/', re.IGNORECASE),
                re.compile(r'scp\s+.*/etc/passwd', re.IGNORECASE),
                re.compile(r'curl\s+.*--upload-file\s+/etc/', re.IGNORECASE),
                re.compile(r'base64\s+/etc/(shadow|passwd)', re.IGNORECASE),
                re.compile(r'cat\s+/etc/shadow\s*\|', re.IGNORECASE),
                re.compile(r'exfil|loot\s+.*shadow', re.IGNORECASE),
            ],
        ),
        (
            'password_cracking',
            'HIGH',
            'BASH_HISTORY_PASSWORD_CRACKING',
            [
                re.compile(r'\bhashcat\b', re.IGNORECASE),
                re.compile(r'\bjohn\s+.*--wordlist', re.IGNORECASE),
                re.compile(r'\bhydra\b.*-P\b', re.IGNORECASE),
                re.compile(r'\bmedusa\b.*-P\b', re.IGNORECASE),
                re.compile(r'\bcrack\b.*shadow', re.IGNORECASE),
                re.compile(r'unshadow\b', re.IGNORECASE),
            ],
        ),
        (
            'network_scan',
            'MEDIUM',
            'BASH_HISTORY_NETWORK_SCAN',
            [
                re.compile(r'\bnmap\b', re.IGNORECASE),
                re.compile(r'\bmasscan\b', re.IGNORECASE),
                re.compile(r'\bzmap\b', re.IGNORECASE),
                re.compile(r'\barp-scan\b', re.IGNORECASE),
                re.compile(r'\bnaabu\b', re.IGNORECASE),
                re.compile(r'\bhttpx\b', re.IGNORECASE),
                re.compile(r'\bnuclei\b', re.IGNORECASE),
            ],
        ),
        (
            'track_clearing',
            'HIGH',
            'BASH_HISTORY_TRACK_CLEARING',
            [
                re.compile(r'history\s+-[cw]\b', re.IGNORECASE),
                re.compile(r'rm\s+.*\.bash_history', re.IGNORECASE),
                re.compile(r'unset\s+HISTFILE\b', re.IGNORECASE),
                re.compile(r'export\s+HISTSIZE=0\b', re.IGNORECASE),
                re.compile(r'>\s*~?/root/\.bash_history', re.IGNORECASE),
                re.compile(r'>\s*/home/\w+/\.bash_history', re.IGNORECASE),
                re.compile(r'shred\s+.*\.bash_history', re.IGNORECASE),
            ],
        ),
        (
            'cron_modification',
            'HIGH',
            'BASH_HISTORY_CRON_MODIFICATION',
            [
                re.compile(r'crontab\s+-[el]\b', re.IGNORECASE),
                re.compile(r'echo\s+.*>>\s*/etc/cron', re.IGNORECASE),
                re.compile(r'tee\s+/etc/cron', re.IGNORECASE),
                re.compile(r'cp\s+.*\s+/etc/cron', re.IGNORECASE),
                re.compile(r'>\s*/etc/cron\.(d|daily|hourly|weekly)/', re.IGNORECASE),
            ],
        ),
        (
            'persistence',
            'HIGH',
            'BASH_HISTORY_PERSISTENCE',
            [
                re.compile(r'echo\s+.*>>\s*/etc/rc\.local', re.IGNORECASE),
                re.compile(r'systemctl\s+enable\b', re.IGNORECASE),
                re.compile(r'cp\s+.*\s+/etc/init\.d/', re.IGNORECASE),
                re.compile(r'update-rc\.d\b', re.IGNORECASE),
                re.compile(r'chkconfig\s+.*on\b', re.IGNORECASE),
                re.compile(r'echo\s+.*>>\s*~?/\.bashrc', re.IGNORECASE),
                re.compile(r'echo\s+.*>>\s*~?/\.profile', re.IGNORECASE),
                re.compile(r'echo\s+.*authorized_keys', re.IGNORECASE),
            ],
        ),
    ]

    # Collect history file paths
    history_paths = []
    try:
        home_histories = glob.glob('/home/*/.bash_history')
        history_paths.extend(home_histories)
    except Exception:
        pass
    history_paths.append('/root/.bash_history')

    # Per-file, per-category hit counts
    for hist_path in history_paths:
        try:
            with open(hist_path, 'r', errors='replace') as fh:
                lines = fh.readlines()
        except OSError:
            continue

        counts = {}  # category_key -> hit_count
        for line in lines:
            for cat_key, _sev, _title, patterns in categories:
                if cat_key not in counts:
                    counts[cat_key] = 0
                for pat in patterns:
                    if pat.search(line):
                        counts[cat_key] += 1
                        break  # one match per category per line

        for cat_key, severity, title, _patterns in categories:
            n = counts.get(cat_key, 0)
            if n > 0:
                findings.append(_make_finding(
                    severity,
                    title,
                    f'{hist_path}: {n} line(s) matching {cat_key.replace("_", " ")} pattern(s); '
                    f'indicates adversarial activity consistent with Black Hat Bash ch8/9/10/12 TTPs',
                ))

    if not history_paths or not findings:
        # No readable history files or no hits — emit INFO
        readable = sum(1 for p in history_paths if os.path.isfile(p))
        findings.append(_make_finding(
            'INFO',
            'BASH_HISTORY_SCAN_COMPLETE',
            f'Scanned {len(history_paths)} candidate history path(s), {readable} readable; '
            'no offensive patterns detected',
        ))

    return findings


def detect_writable_system_paths() -> list:
    """Detect security-relevant writable paths: world-writable dirs/files, auth files,
    cron files, linker config, system binaries, and SUID/SGID in unusual locations.

    Based on Black Hat Bash ch9 (privilege escalation via SUID/writable paths) and
    ch10 (persistence via cron/init), covering the writable-surface enumeration
    discipline from the operating methodology.

    Returns List[dict]: each dict has {severity, title, detail, host, port}.
    """
    findings = []

    def _is_world_writable(path: str) -> bool:
        try:
            return bool(os.stat(path).st_mode & stat.S_IWOTH)
        except OSError:
            return False

    def _mode(path: str) -> int:
        try:
            return os.stat(path).st_mode
        except OSError:
            return 0

    # --- World-writable directory checks ---
    dir_checks = [
        ('/tmp',       'INFO',     'WRITABLE_TMP_DIR',            'expected tmpfs; confirm noexec mount option'),
        ('/var/tmp',   'INFO',     'WRITABLE_VAR_TMP_DIR',        'expected; confirm noexec mount option'),
        ('/etc',       'CRITICAL', 'WRITABLE_ETC_DIRECTORY',      'world-writable /etc allows config replacement, shadow overwrite, sudoers injection'),
        ('/usr/bin',   'CRITICAL', 'WRITABLE_SYSTEM_BINARY_DIR',  'world-writable /usr/bin enables binary replacement for persistence or privilege escalation'),
        ('/usr/sbin',  'CRITICAL', 'WRITABLE_SYSTEM_BINARY_DIR',  'world-writable /usr/sbin enables binary replacement for persistence or privilege escalation'),
        ('/bin',       'CRITICAL', 'WRITABLE_SYSTEM_BINARY_DIR',  'world-writable /bin enables binary replacement for persistence or privilege escalation'),
        ('/sbin',      'CRITICAL', 'WRITABLE_SYSTEM_BINARY_DIR',  'world-writable /sbin enables binary replacement for persistence or privilege escalation'),
        ('/usr/lib',   'HIGH',     'WRITABLE_LIBRARY_DIRECTORY',  'world-writable library dir allows shared-object replacement; loaded at runtime by privileged processes'),
        ('/lib',       'HIGH',     'WRITABLE_LIBRARY_DIRECTORY',  'world-writable /lib allows libc/libpthread replacement; system-wide impact at next process spawn'),
        ('/lib64',     'HIGH',     'WRITABLE_LIBRARY_DIRECTORY',  'world-writable /lib64 allows 64-bit dynamic linker replacement'),
    ]
    for path, severity, title, note in dir_checks:
        if os.path.isdir(path) and _is_world_writable(path):
            m = _mode(path)
            findings.append(_make_finding(
                severity,
                title,
                f'{path} mode={oct(m)}: {note}',
            ))

    # --- World-writable sensitive file checks ---
    auth_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/sudoers.d']
    for path in auth_files:
        if os.path.exists(path) and _is_world_writable(path):
            m = _mode(path)
            findings.append(_make_finding(
                'CRITICAL',
                'WRITABLE_AUTH_FILE',
                f'{path} mode={oct(m)}: world-writable authentication/authorization file; '
                'direct root escalation via passwd overwrite or sudoers injection',
            ))

    # /etc/crontab and /etc/cron.d/*
    cron_paths = ['/etc/crontab']
    try:
        cron_d = [
            os.path.join('/etc/cron.d', e)
            for e in os.listdir('/etc/cron.d')
            if os.path.isfile(os.path.join('/etc/cron.d', e))
        ]
        cron_paths.extend(cron_d)
    except OSError:
        pass
    for path in cron_paths:
        if os.path.exists(path) and _is_world_writable(path):
            m = _mode(path)
            findings.append(_make_finding(
                'HIGH',
                'WRITABLE_CRON_FILE',
                f'{path} mode={oct(m)}: world-writable cron file; '
                'arbitrary command injection executed as cron owner (often root)',
            ))

    # /etc/ld.so.conf and /etc/ld.so.conf.d/*
    ldconf_paths = ['/etc/ld.so.conf']
    try:
        ldconf_d_dir = '/etc/ld.so.conf.d'
        if os.path.isdir(ldconf_d_dir):
            ldconf_d = [
                os.path.join(ldconf_d_dir, e)
                for e in os.listdir(ldconf_d_dir)
                if os.path.isfile(os.path.join(ldconf_d_dir, e))
            ]
            ldconf_paths.extend(ldconf_d)
    except OSError:
        pass
    for path in ldconf_paths:
        if os.path.exists(path) and _is_world_writable(path):
            m = _mode(path)
            findings.append(_make_finding(
                'HIGH',
                'WRITABLE_LDCONF_FILE',
                f'{path} mode={oct(m)}: world-writable linker config; '
                'attacker can inject malicious library search path; '
                'run ldconfig after write to activate without reboot',
            ))

    # World-writable binaries in /usr/bin and /bin
    for bin_dir in ('/usr/bin', '/bin', '/usr/sbin', '/sbin'):
        try:
            for entry in os.scandir(bin_dir):
                if entry.is_file(follow_symlinks=False) and _is_world_writable(entry.path):
                    m = _mode(entry.path)
                    findings.append(_make_finding(
                        'CRITICAL',
                        'WRITABLE_SYSTEM_BINARY',
                        f'{entry.path} mode={oct(m)}: world-writable system binary; '
                        'replace with backdoored version for persistence or privilege escalation',
                    ))
        except OSError:
            pass

    # --- SUID/SGID in unusual locations ---
    unusual_roots = ['/home', '/tmp', '/var', '/opt', '/srv', '/run/user']
    for root in unusual_roots:
        if not os.path.isdir(root):
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                # Prune deep /proc or /sys if accidentally reachable
                dirnames[:] = [d for d in dirnames if d not in ('proc', 'sys')]
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        st = os.stat(fpath)
                    except OSError:
                        continue
                    mode = st.st_mode
                    if mode & stat.S_ISUID:
                        findings.append(_make_finding(
                            'CRITICAL',
                            'SUID_IN_UNUSUAL_PATH',
                            f'{fpath} mode={oct(mode)}: SUID bit set outside standard binary dirs; '
                            'executes as file owner (often root) regardless of invoking user; '
                            'classic privilege escalation vector per Black Hat Bash ch9',
                        ))
                    elif mode & stat.S_ISGID and stat.S_ISREG(mode):
                        findings.append(_make_finding(
                            'HIGH',
                            'SGID_IN_UNUSUAL_PATH',
                            f'{fpath} mode={oct(mode)}: SGID bit set in non-standard path outside /usr; '
                            'executes with group privileges of file owner group; review group membership',
                        ))
        except OSError:
            pass

    # --- /proc/sysrq-trigger writable check ---
    sysrq = '/proc/sysrq-trigger'
    if os.path.exists(sysrq):
        try:
            if os.access(sysrq, os.W_OK):
                findings.append(_make_finding(
                    'HIGH',
                    'SYSRQ_TRIGGER_WRITABLE',
                    f'{sysrq} is writable by current user; '
                    'allows kernel magic SysRq commands (reboot, OOM-kill, sync) '
                    'without root; can be used to trigger denial-of-service or '
                    'force crash-dump for subsequent memory analysis',
                ))
        except OSError:
            pass

    if not findings:
        findings.append(_make_finding(
            'INFO',
            'WRITABLE_SYSTEM_PATHS_SCAN_COMPLETE',
            'No world-writable system directories, sensitive files, or SUID/SGID '
            'in unusual paths detected',
        ))

    return findings


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == 'list':
            # List all processes
            enum = ProcessEnumerator()
            procs = enum.list_all_processes()
            print(f"Total processes: {len(procs)}\n")
            print(f"{'PID':<8} {'NAME':<20} CMDLINE")
            print("-" * 80)
            for p in procs[:20]:  # First 20
                print(f"{p['pid']:<8} {p['name']:<20} {p['cmdline'][:40]}")
        else:
            pid = int(sys.argv[1])
            enum = ProcessEnumerator(pid)
            print(enum.report())
    else:
        # Current process
        enum = ProcessEnumerator()
        print(enum.report())
