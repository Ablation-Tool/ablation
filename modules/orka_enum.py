#!/usr/bin/env python3
"""
Orka Platform Enumeration Module
Synthesized from: MAC-STADIUM reverse engineering findings

Enumerate MacStadium Orka platform (K8s-based macOS virtualization).
"""

import subprocess
import json
import os
import requests
from pathlib import Path

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
            'findings': self.findings
        }
    
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
