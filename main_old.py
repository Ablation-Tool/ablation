#!/usr/bin/env python3
"""
Ablation - Autonomous Reverse Engineering Tool

Deploy inside compromised system to autonomously reverse engineer unknown platform.

Usage:
    ./ablation              - Full autonomous analysis
    ./ablation --quick      - Quick platform fingerprint only
    ./ablation --process PID - Analyze specific process
    ./ablation --binary FILE - Analyze specific binary
    ./ablation --syscalls PID [duration] - Trace syscalls for process
    ./ablation --privesc     - Enumerate privilege escalation paths
"""

import sys
import json
from pathlib import Path

# Core modules
sys.path.insert(0, str(Path(__file__).parent / 'core'))
sys.path.insert(0, str(Path(__file__).parent / 'modules'))

from platform_detect import PlatformDetector
from binary_parser import BinaryParser
from disasm_engine import DisasmEngine
from process_enum import ProcessEnumerator
from syscall_trace import SyscallTracer
from privesc_enum import PrivescEnumerator

class Ablation:
    """Main reverse engineering orchestrator"""
    
    def __init__(self):
        self.platform = None
        self.processes = []
        self.binaries = []
        self.findings = {
            'platform': {},
            'processes': [],
            'binaries': [],
            'vulnerabilities': [],
            'interesting': [],
            'privesc_paths': []
        }
        self.version = "2.0.0"
    
    def banner(self):
        """Display banner"""
        print("""
    ___    __    __    ___  ___________  ____  _  __
   / _ |  / /   / /   / _ |/_  __/  _/ |/ / | / /
  / __ | / _ \ / /__ / __ | / /  _/ //    /  |/ / 
 /_/ |_|/_.__//____//_/ |_|/_/ /___/_/|_/_/|___/  
                                                   
 Autonomous Reverse Engineering Tool v{}
 Deploy INSIDE systems | Zero dependencies
        """.format(self.version))
    
    def run_autonomous(self):
        """Full autonomous analysis"""
        self.banner()
        print("[*] Ablation - Autonomous Mode")
        print("[*] Analyzing compromised system...")
        print()
        
        # Step 1: Platform detection
        print("[1/6] Platform Detection")
        self.detect_platform()
        print(f"  OS: {self.findings['platform']['os']} {self.findings['platform']['arch_bits']}bit")
        print(f"  Kernel: {self.findings['platform'].get('kernel', 'N/A')}")
        print()
        
        # Step 2: Process enumeration
        print("[2/6] Process Enumeration")
        self.enumerate_processes()
        print(f"  Found {len(self.findings['processes'])} running processes")
        print()
        
        # Step 3: Binary discovery
        print("[3/6] Binary Discovery")
        self.discover_binaries()
        print(f"  Found {len(self.findings['binaries'])} interesting binaries")
        print()
        
        # Step 4: Vulnerability hunting
        print("[4/6] Vulnerability Analysis")
        self.hunt_vulnerabilities()
        print(f"  Identified {len(self.findings['vulnerabilities'])} potential vulnerabilities")
        print()
        
        # Step 5: Privilege escalation paths
        print("[5/6] Privilege Escalation Enumeration")
        self.enumerate_privesc()
        print(f"  Found {len(self.findings['privesc_paths'])} potential paths")
        print()
        
        # Step 6: Generate report
        print("[6/6] Report Generation")
        report_path = self.generate_report()
        print(f"  Report saved: {report_path}")
        print()
        
        return self.findings
    
    def detect_platform(self):
        """Detect platform characteristics"""
        detector = PlatformDetector()
        detector.detect_all()
        self.findings['platform'] = detector.info
        self.platform = detector
        return detector.info
    
    def enumerate_processes(self):
        """Enumerate all running processes"""
        enum = ProcessEnumerator()
        procs = enum.list_all_processes()
        
        # Find interesting processes
        interesting_names = ['ssh', 'sshd', 'apache', 'nginx', 'mysql', 'postgres', 
                           'docker', 'kubelet', 'redis', 'mongo', 'sudo', 'su']
        
        for proc in procs:
            entry = {
                'pid': proc['pid'],
                'name': proc['name'],
                'cmdline': proc['cmdline']
            }
            
            # Flag interesting ones
            if any(name in proc['name'].lower() for name in interesting_names):
                entry['interesting'] = True
                self.findings['interesting'].append({
                    'type': 'process',
                    'name': proc['name'],
                    'detail': f"PID {proc['pid']}"
                })
            
            self.findings['processes'].append(entry)
        
        return procs
    
    def discover_binaries(self):
        """Discover interesting binaries"""
        search_paths = [
            '/bin',
            '/sbin',
            '/usr/bin',
            '/usr/sbin',
            '/usr/local/bin',
            '/opt'
        ]
        
        interesting_binaries = []
        
        for path in search_paths:
            path_obj = Path(path)
            if not path_obj.exists():
                continue
            
            try:
                for binary in path_obj.iterdir():
                    if binary.is_file():
                        try:
                            parser = BinaryParser(binary)
                            info = parser.parse()
                            
                            entry = {
                                'path': str(binary),
                                'format': info['format'],
                                'bits': info.get('bits'),
                                'entry': info.get('entry_point')
                            }
                            
                            interesting_binaries.append(entry)
                            
                            if len(interesting_binaries) >= 50:
                                break
                        except:
                            pass
            except:
                pass
            
            if len(interesting_binaries) >= 50:
                break
        
        self.findings['binaries'] = interesting_binaries
        return interesting_binaries
    
    def hunt_vulnerabilities(self):
        """Hunt for common vulnerabilities"""
        vulns = []
        
        if self.findings['platform'].get('security'):
            sec = self.findings['platform']['security']
            
            # ASLR disabled
            if sec.get('aslr') == 'disabled':
                vulns.append({
                    'severity': 'HIGH',
                    'type': 'ASLR Disabled',
                    'description': 'Address Space Layout Randomization is disabled',
                    'impact': 'Easier exploitation of memory corruption bugs',
                    'remediation': 'Enable ASLR: echo 2 > /proc/sys/kernel/randomize_va_space'
                })
        
        # Check for ptrace availability
        if self.findings['platform'].get('capabilities', {}).get('ptrace_scope') == 0:
            vulns.append({
                'severity': 'MEDIUM',
                'type': 'Unrestricted ptrace',
                'description': 'ptrace is unrestricted (ptrace_scope=0)',
                'impact': 'Any process can debug any other process',
                'remediation': 'Restrict ptrace: echo 1 > /proc/sys/kernel/yama/ptrace_scope'
            })
        
        self.findings['vulnerabilities'] = vulns
        return vulns
    
    def enumerate_privesc(self):
        """Enumerate privilege escalation paths"""
        enum = PrivescEnumerator()
        paths = enum.enumerate_all()
        self.findings['privesc_paths'] = paths
        return paths
    
    def analyze_process(self, pid):
        """Deep analysis of specific process"""
        enum = ProcessEnumerator(pid)
        
        report = {
            'pid': pid,
            'maps': enum.get_memory_maps(),
            'modules': enum.get_loaded_modules(),
            'fds': enum.get_open_files(),
            'env': enum.get_environment(),
            'wx_regions': enum.find_writable_executable()
        }
        
        return report
    
    def analyze_binary(self, filepath):
        """Deep analysis of specific binary"""
        parser = BinaryParser(filepath)
        info = parser.parse()
        
        # Disassemble entry point
        with open(filepath, 'rb') as f:
            if info.get('entry_point'):
                entry = int(info['entry_point'], 16)
                f.seek(entry if entry < 1000000 else 0)
                code = f.read(512)
                
                engine = DisasmEngine()
                disasm = engine.disassemble(code, entry, count=50)
                
                info['disassembly'] = disasm[:20]
        
        return info
    
    def trace_syscalls(self, pid, duration=5):
        """Trace syscalls for a process"""
        tracer = SyscallTracer(pid)
        return tracer.trace_process(duration)
    
    def generate_report(self):
        """Generate comprehensive report"""
        report_path = Path('/tmp/ablation-report.json')
        
        with open(report_path, 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        # Text summary
        summary_path = Path('/tmp/ablation-summary.txt')
        with open(summary_path, 'w') as f:
            f.write("="*60 + "\n")
            f.write("ABLATION - AUTONOMOUS ANALYSIS REPORT\n")
            f.write("="*60 + "\n\n")
            
            f.write("PLATFORM\n")
            f.write("-"*60 + "\n")
            p = self.findings['platform']
            f.write(f"OS: {p.get('os')} {p.get('os_release', '')}\n")
            f.write(f"Architecture: {p.get('machine')} ({p.get('arch_bits')} bit)\n")
            if 'kernel' in p:
                f.write(f"Kernel: {p['kernel']}\n")
            f.write("\n")
            
            f.write("PROCESSES\n")
            f.write("-"*60 + "\n")
            f.write(f"Total: {len(self.findings['processes'])}\n")
            interesting_procs = [p for p in self.findings['processes'] if p.get('interesting')]
            if interesting_procs:
                f.write(f"Interesting: {len(interesting_procs)}\n")
                for p in interesting_procs[:10]:
                    f.write(f"  PID {p['pid']}: {p['name']}\n")
            f.write("\n")
            
            f.write("VULNERABILITIES\n")
            f.write("-"*60 + "\n")
            for vuln in self.findings['vulnerabilities']:
                f.write(f"[{vuln['severity']}] {vuln['type']}\n")
                f.write(f"  {vuln['description']}\n")
                f.write(f"  Impact: {vuln['impact']}\n")
                f.write(f"  Fix: {vuln['remediation']}\n\n")
            
            f.write("PRIVILEGE ESCALATION PATHS\n")
            f.write("-"*60 + "\n")
            for path in self.findings['privesc_paths']:
                f.write(f"[{path['severity']}] {path['category']}\n")
                f.write(f"  {path['description']}\n")
                if 'exploit' in path:
                    f.write(f"  Exploit: {path['exploit']}\n")
                f.write("\n")
        
        return summary_path

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Ablation - Autonomous Reverse Engineering')
    parser.add_argument('--quick', action='store_true', help='Quick platform fingerprint only')
    parser.add_argument('--process', type=int, metavar='PID', help='Analyze specific process')
    parser.add_argument('--binary', metavar='FILE', help='Analyze specific binary')
    parser.add_argument('--syscalls', type=int, metavar='PID', help='Trace syscalls for PID')
    parser.add_argument('--duration', type=int, default=5, help='Syscall trace duration (seconds)')
    parser.add_argument('--privesc', action='store_true', help='Enumerate privilege escalation paths')
    
    args = parser.parse_args()
    
    ablation = Ablation()
    
    if args.quick:
        ablation.banner()
        info = ablation.detect_platform()
        print(ablation.platform.report())
    
    elif args.process:
        ablation.banner()
        report = ablation.analyze_process(args.process)
        print(json.dumps(report, indent=2))
    
    elif args.binary:
        ablation.banner()
        info = ablation.analyze_binary(args.binary)
        print(json.dumps(info, indent=2))
    
    elif args.syscalls:
        ablation.banner()
        print(f"[*] Tracing syscalls for PID {args.syscalls} ({args.duration}s)...")
        tracer = SyscallTracer(args.syscalls)
        stats = tracer.trace_process(args.duration)
        print("\n" + tracer.report(stats))
    
    elif args.privesc:
        ablation.banner()
        print("[*] Enumerating privilege escalation paths...")
        enum = PrivescEnumerator()
        paths = enum.enumerate_all()
        print(enum.report())
    
    else:
        ablation.run_autonomous()
        print("[+] Analysis complete!")
        print(f"[+] Full report: /tmp/ablation-report.json")
        print(f"[+] Summary: /tmp/ablation-summary.txt")

if __name__ == '__main__':
    import os
    main()

# Import container modules at top with others
from docker_enum import DockerEnumerator
from k8s_enum import K8sEnumerator
