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
