#!/usr/bin/env python3
"""
Process Enumeration Module
Synthesized from: Learning Linux Binary Analysis, Linux System Programming

Enumerate running processes, loaded modules, memory maps.
"""

import os
import re
from pathlib import Path

class ProcessEnumerator:
    """Enumerate and analyze processes"""
    
    def __init__(self, pid=None):
        self.pid = pid or os.getpid()
        self.proc_path = Path(f"/proc/{self.pid}")
        
    def list_all_processes(self):
        """List all running processes"""
        procs = []
        for entry in Path("/proc").iterdir():
            if entry.is_dir() and entry.name.isdigit():
                pid = int(entry.name)
                try:
                    with open(entry / "comm") as f:
                        name = f.read().strip()
                    with open(entry / "cmdline") as f:
                        cmdline = f.read().replace('\x00', ' ').strip()
                    
                    procs.append({
                        'pid': pid,
                        'name': name,
                        'cmdline': cmdline or name
                    })
                except:
                    pass
        
        return sorted(procs, key=lambda x: x['pid'])
    
    def get_memory_maps(self):
        """Read process memory maps"""
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
        fds = []
        fd_path = self.proc_path / "fd"
        
        try:
            for fd in fd_path.iterdir():
                if fd.is_symlink():
                    target = os.readlink(str(fd))
                    fds.append({
                        'fd': int(fd.name),
                        'target': target
                    })
        except:
            pass
        
        return sorted(fds, key=lambda x: x['fd'])
    
    def get_environment(self):
        """Read process environment variables"""
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
    
    def report(self):
        """Generate full process report"""
        lines = []
        lines.append(f"Process: PID {self.pid}")
        
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
