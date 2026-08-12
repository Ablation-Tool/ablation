#!/usr/bin/env python3
"""
Kubernetes Enumeration Module
Synthesized from: Kubernetes security best practices, pod escape techniques

Enumerate K8s pods, services, secrets, RBAC, service accounts.
"""

import subprocess
import json
import os
from pathlib import Path

class K8sEnumerator:
    """Enumerate Kubernetes environment"""
    
    def __init__(self):
        self.in_k8s = False
        self.namespace = None
        self.service_account = None
        self.token = None
        self.pods = []
        self.services = []
        self.secrets = []
        self.configmaps = []
        self.rbac = []
        self.escape_vectors = []
        
    def enumerate_all(self):
        """Run all Kubernetes enumeration"""
        self.check_in_k8s()
        
        if self.in_k8s:
            self.get_service_account()
            self.get_token()
            self.check_kubectl_access()
            
            # Try to enumerate with kubectl if available
            if self.check_kubectl_access():
                self.get_pods()
                self.get_services()
                self.get_secrets()
                self.get_configmaps()
                self.check_rbac()
            
            self.check_escape_vectors()
        
        return {
            'in_k8s': self.in_k8s,
            'namespace': self.namespace,
            'service_account': self.service_account,
            'has_token': bool(self.token),
            'pods': self.pods,
            'services': self.services,
            'secrets': self.secrets,
            'configmaps': self.configmaps,
            'rbac': self.rbac,
            'escape_vectors': self.escape_vectors
        }
    
    def check_in_k8s(self):
        """Detect if running inside Kubernetes"""
        # Check for service account
        if Path('/var/run/secrets/kubernetes.io/serviceaccount').exists():
            self.in_k8s = True
            return True
        
        # Check environment variables
        if os.getenv('KUBERNETES_SERVICE_HOST'):
            self.in_k8s = True
            return True
        
        # Check cgroup
        try:
            with open('/proc/1/cgroup') as f:
                if 'kubepods' in f.read():
                    self.in_k8s = True
                    return True
        except:
            pass
        
        return False
    
    def get_service_account(self):
        """Get service account name"""
        sa_path = Path('/var/run/secrets/kubernetes.io/serviceaccount')
        
        if sa_path.exists():
            # Get namespace
            try:
                with open(sa_path / 'namespace') as f:
                    self.namespace = f.read().strip()
            except:
                pass
            
            # Service account name from env or default
            self.service_account = os.getenv('SERVICEACCOUNT', 'default')
        
        return self.service_account
    
    def get_token(self):
        """Get service account token"""
        token_path = Path('/var/run/secrets/kubernetes.io/serviceaccount/token')
        
        if token_path.exists():
            try:
                with open(token_path) as f:
                    self.token = f.read().strip()
            except:
                pass
        
        return self.token
    
    def check_kubectl_access(self):
        """Check if kubectl is available and working"""
        try:
            result = subprocess.run(
                ['kubectl', 'auth', 'can-i', '--list'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def get_pods(self):
        """List pods in current namespace"""
        try:
            result = subprocess.run(
                ['kubectl', 'get', 'pods', '-o', 'json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for item in data.get('items', []):
                    self.pods.append({
                        'name': item['metadata']['name'],
                        'namespace': item['metadata']['namespace'],
                        'status': item['status']['phase'],
                        'ip': item['status'].get('podIP', '')
                    })
        except:
            pass
        
        return self.pods
    
    def get_services(self):
        """List services"""
        try:
            result = subprocess.run(
                ['kubectl', 'get', 'services', '-o', 'json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for item in data.get('items', []):
                    self.services.append({
                        'name': item['metadata']['name'],
                        'namespace': item['metadata']['namespace'],
                        'type': item['spec']['type'],
                        'cluster_ip': item['spec'].get('clusterIP', '')
                    })
        except:
            pass
        
        return self.services
    
    def get_secrets(self):
        """List secrets (if permitted)"""
        try:
            result = subprocess.run(
                ['kubectl', 'get', 'secrets', '-o', 'json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for item in data.get('items', []):
                    self.secrets.append({
                        'name': item['metadata']['name'],
                        'namespace': item['metadata']['namespace'],
                        'type': item['type']
                    })
        except:
            pass
        
        return self.secrets
    
    def get_configmaps(self):
        """List configmaps"""
        try:
            result = subprocess.run(
                ['kubectl', 'get', 'configmaps', '-o', 'json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for item in data.get('items', []):
                    self.configmaps.append({
                        'name': item['metadata']['name'],
                        'namespace': item['metadata']['namespace']
                    })
        except:
            pass
        
        return self.configmaps
    
    def check_rbac(self):
        """Check RBAC permissions"""
        permissions = [
            'get pods',
            'list pods',
            'create pods',
            'delete pods',
            'get secrets',
            'list secrets',
            'create secrets',
            'get nodes',
            'list nodes',
            '*'  # Cluster admin
        ]
        
        for perm in permissions:
            try:
                result = subprocess.run(
                    ['kubectl', 'auth', 'can-i'] + perm.split(),
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                
                if result.returncode == 0 and 'yes' in result.stdout.lower():
                    self.rbac.append({
                        'permission': perm,
                        'allowed': True
                    })
            except:
                pass
        
        return self.rbac
    
    def check_escape_vectors(self):
        """Check for Kubernetes escape vectors"""
        self.escape_vectors = []
        
        # Service account token available
        if self.token:
            self.escape_vectors.append({
                'type': 'Service Account Token',
                'severity': 'HIGH',
                'description': 'Service account token accessible',
                'exploit': 'Use token to authenticate to K8s API'
            })
        
        # Privileged pod (check via capabilities or proc)
        try:
            with open('/proc/self/status') as f:
                for line in f:
                    if line.startswith('CapEff:'):
                        cap_eff = int(line.split()[1], 16)
                        if cap_eff == 0x3fffffffff:
                            self.escape_vectors.append({
                                'type': 'Privileged Pod',
                                'severity': 'CRITICAL',
                                'description': 'Pod running with privileged: true',
                                'exploit': 'Full host access via /dev, /proc, /sys'
                            })
        except:
            pass
        
        # hostPath mounts
        try:
            with open('/proc/self/mountinfo') as f:
                for line in f:
                    if '/host' in line or '/var/run/docker.sock' in line:
                        self.escape_vectors.append({
                            'type': 'Dangerous hostPath Mount',
                            'severity': 'CRITICAL',
                            'description': 'Host filesystem or Docker socket mounted',
                            'exploit': 'Access host filesystem or Docker API'
                        })
                        break
        except:
            pass
        
        # Excessive RBAC permissions
        dangerous_perms = ['create pods', 'delete pods', '*']
        for perm in self.rbac:
            if any(d in perm['permission'] for d in dangerous_perms):
                self.escape_vectors.append({
                    'type': 'Excessive RBAC',
                    'severity': 'HIGH',
                    'description': f"Can {perm['permission']}",
                    'exploit': 'Create privileged pods, access secrets'
                })
        
        return self.escape_vectors
    
    def report(self):
        """Generate human-readable report"""
        lines = []
        lines.append("="*60)
        lines.append("KUBERNETES ENUMERATION")
        lines.append("="*60)
        
        lines.append(f"\nIn K8s: {self.in_k8s}")
        
        if self.in_k8s:
            lines.append(f"Namespace: {self.namespace or 'N/A'}")
            lines.append(f"Service Account: {self.service_account or 'N/A'}")
            lines.append(f"Has Token: {bool(self.token)}")
            
            if self.pods:
                lines.append(f"\nPods: {len(self.pods)}")
                for pod in self.pods[:5]:
                    lines.append(f"  {pod['name']} ({pod['status']})")
            
            if self.services:
                lines.append(f"\nServices: {len(self.services)}")
                for svc in self.services[:5]:
                    lines.append(f"  {svc['name']} ({svc['type']})")
            
            if self.secrets:
                lines.append(f"\nSecrets Accessible: {len(self.secrets)}")
            
            if self.rbac:
                lines.append(f"\nRBAC Permissions: {len(self.rbac)}")
                for perm in self.rbac:
                    lines.append(f"  ✓ {perm['permission']}")
            
            if self.escape_vectors:
                lines.append(f"\nEscape Vectors: {len(self.escape_vectors)}")
                for vec in self.escape_vectors:
                    lines.append(f"  [{vec['severity']}] {vec['type']}")
                    lines.append(f"    {vec['description']}")
        
        return "\n".join(lines)

if __name__ == '__main__':
    enum = K8sEnumerator()
    enum.enumerate_all()
    print(enum.report())
