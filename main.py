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
    ./ablation --docker      - Docker enumeration
    ./ablation --k8s         - Kubernetes enumeration
    ./ablation --orka        - Orka platform enumeration
    ./ablation --containers  - Full container analysis (Docker + K8s + Orka)
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
from network_analyze import NetworkAnalyzer
from docker_enum import DockerEnumerator
from k8s_enum import K8sEnumerator
from orka_enum import OrkaEnumerator

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
            'privesc_paths': [],
            'network': {},
            'docker': {},
            'kubernetes': {},
            'orka': {}
        }
        self.version = "2.2.0"
    
    def banner(self):
        """Display banner"""
        print(r"""
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
        print("[1/8] Platform Detection")
        self.detect_platform()
        print(f"  OS: {self.findings['platform']['os']} {self.findings['platform']['arch_bits']}bit")
        print(f"  Kernel: {self.findings['platform'].get('kernel', 'N/A')}")
        print()
        
        # Step 2: Process enumeration
        print("[2/8] Process Enumeration")
        self.enumerate_processes()
        print(f"  Found {len(self.findings['processes'])} running processes")
        print()
        
        # Step 3: Binary discovery
        print("[3/8] Binary Discovery")
        self.discover_binaries()
        print(f"  Found {len(self.findings['binaries'])} interesting binaries")
        print()
        
        # Step 4: Network analysis
        print("[4/8] Network Analysis")
        self.analyze_network()
        print(f"  Interfaces: {len(self.findings['network'].get('interfaces', []))}")
        print(f"  Listening: {len(self.findings['network'].get('listening', []))}")
        print()
        
        # Step 5: Container/platform enumeration
        print("[5/8] Container/Platform Enumeration")
        self.enumerate_containers()
        docker_info = self.findings['docker']
        k8s_info = self.findings['kubernetes']
        orka_info = self.findings['orka']
        
        if docker_info.get('in_container') or docker_info.get('socket_access'):
            print(f"  Docker: In container={docker_info.get('in_container')}, Socket={docker_info.get('socket_access')}")
        if k8s_info.get('in_k8s'):
            print(f"  Kubernetes: Namespace={k8s_info.get('namespace')}")
        if orka_info.get('in_orka_vm') or orka_info.get('orka_api_reachable'):
            print(f"  Orka: VM={orka_info.get('in_orka_vm')}, API={orka_info.get('orka_api_reachable')}")
        print()
        
        # Step 6: Vulnerability hunting
        print("[6/8] Vulnerability Analysis")
        self.hunt_vulnerabilities()
        print(f"  Identified {len(self.findings['vulnerabilities'])} potential vulnerabilities")
        print()
        
        # Step 7: Privilege escalation paths
        print("[7/8] Privilege Escalation Enumeration")
        self.enumerate_privesc()
        print(f"  Found {len(self.findings['privesc_paths'])} potential paths")
        print()
        
        # Step 8: Generate report
        print("[8/8] Report Generation")
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
                           'docker', 'kubelet', 'redis', 'mongo', 'sudo', 'su',
                           'containerd', 'dockerd', 'kube-proxy', 'orka']
        
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
    
    def analyze_network(self):
        """Analyze network configuration"""
        analyzer = NetworkAnalyzer()
        network_info = analyzer.enumerate_all()
        self.findings['network'] = network_info
        return network_info
    
    def enumerate_containers(self):
        """Enumerate Docker, Kubernetes, and Orka"""
        # Docker
        docker_enum = DockerEnumerator()
        self.findings['docker'] = docker_enum.enumerate_all()
        
        # Kubernetes
        k8s_enum = K8sEnumerator()
        self.findings['kubernetes'] = k8s_enum.enumerate_all()
        
        # Orka
        orka_enum = OrkaEnumerator()
        self.findings['orka'] = orka_enum.enumerate_all()
        
        return {
            'docker': self.findings['docker'],
            'kubernetes': self.findings['kubernetes'],
            'orka': self.findings['orka']
        }
    
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
        
        # Container escape vectors
        if self.findings['docker'].get('escape_vectors'):
            for vec in self.findings['docker']['escape_vectors']:
                vulns.append({
                    'severity': vec['severity'],
                    'type': f"Docker: {vec['type']}",
                    'description': vec['description'],
                    'impact': 'Container escape possible',
                    'remediation': vec.get('exploit', 'Review container configuration')
                })
        
        if self.findings['kubernetes'].get('escape_vectors'):
            for vec in self.findings['kubernetes']['escape_vectors']:
                vulns.append({
                    'severity': vec['severity'],
                    'type': f"K8s: {vec['type']}",
                    'description': vec['description'],
                    'impact': 'Pod escape possible',
                    'remediation': vec.get('exploit', 'Review pod security policy')
                })
        
        # Orka findings
        if self.findings['orka'].get('findings'):
            for finding in self.findings['orka']['findings']:
                vulns.append({
                    'severity': finding['severity'],
                    'type': f"Orka: {finding['type']}",
                    'description': finding['description'],
                    'impact': finding.get('exploit', 'Security exposure'),
                    'remediation': 'Review Orka security configuration'
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
            
            f.write("CONTAINERS/PLATFORMS\n")
            f.write("-"*60 + "\n")
            docker_info = self.findings['docker']
            k8s_info = self.findings['kubernetes']
            orka_info = self.findings['orka']
            f.write(f"Docker In Container: {docker_info.get('in_container', False)}\n")
            f.write(f"Docker Socket Access: {docker_info.get('socket_access', False)}\n")
            f.write(f"Kubernetes: {k8s_info.get('in_k8s', False)}\n")
            f.write(f"Orka VM: {orka_info.get('in_orka_vm', False)}\n")
            f.write(f"Orka API: {orka_info.get('orka_api_reachable', False)}\n")
            if orka_info.get('in_orka_vm'):
                f.write(f"  Metadata Server: {orka_info.get('metadata_server', {}).get('available', False)}\n")
            f.write("\n")
            
            f.write("NETWORK\n")
            f.write("-"*60 + "\n")
            net = self.findings['network']
            f.write(f"Interfaces: {len(net.get('interfaces', []))}\n")
            f.write(f"Listening Ports: {len(net.get('listening', []))}\n")
            f.write(f"Active Connections: {len(net.get('connections', []))}\n")
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
                f.write("\n")
            
            f.write("PRIVILEGE ESCALATION PATHS\n")
            f.write("-"*60 + "\n")
            for path in self.findings['privesc_paths']:
                f.write(f"[{path['severity']}] {path['category']}\n")
                f.write(f"  {path['description']}\n")
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
    parser.add_argument('--docker', action='store_true', help='Docker enumeration')
    parser.add_argument('--k8s', action='store_true', help='Kubernetes enumeration')
    parser.add_argument('--orka', action='store_true', help='Orka platform enumeration')
    parser.add_argument('--containers', action='store_true', help='Full container/platform analysis')
    
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
    
    elif args.docker:
        ablation.banner()
        print("[*] Enumerating Docker environment...")
        docker_enum = DockerEnumerator()
        docker_enum.enumerate_all()
        print(docker_enum.report())
    
    elif args.k8s:
        ablation.banner()
        print("[*] Enumerating Kubernetes environment...")
        k8s_enum = K8sEnumerator()
        k8s_enum.enumerate_all()
        print(k8s_enum.report())
    
    elif args.orka:
        ablation.banner()
        print("[*] Enumerating Orka platform...")
        orka_enum = OrkaEnumerator()
        orka_enum.enumerate_all()
        print(orka_enum.report())
    
    elif args.containers:
        ablation.banner()
        print("[*] Full container/platform analysis...\n")
        docker_enum = DockerEnumerator()
        docker_enum.enumerate_all()
        print(docker_enum.report())
        print()
        k8s_enum = K8sEnumerator()
        k8s_enum.enumerate_all()
        print(k8s_enum.report())
        print()
        orka_enum = OrkaEnumerator()
        orka_enum.enumerate_all()
        print(orka_enum.report())
    
    else:
        ablation.run_autonomous()
        print("[+] Analysis complete!")
        print(f"[+] Full report: /tmp/ablation-report.json")
        print(f"[+] Summary: /tmp/ablation-summary.txt")

if __name__ == '__main__':
    import os
    main()
