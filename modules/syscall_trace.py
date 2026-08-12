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
