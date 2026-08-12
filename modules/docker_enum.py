#!/usr/bin/env python3
"""
Docker Enumeration Module
Synthesized from: Docker security best practices, container escape techniques

Enumerate Docker containers, images, volumes, networks, socket access.
"""

import subprocess
import json
import os
import platform as _platform
from pathlib import Path

_IS_MACOS = _platform.system() == 'Darwin'
_IS_LINUX = _platform.system() == 'Linux'

class DockerEnumerator:
    """Enumerate Docker environment"""
    
    def __init__(self):
        self.containers = []
        self.images = []
        self.volumes = []
        self.networks = []
        self.socket_access = False
        self.in_container = False
        self.privileged = False
        self.capabilities = []
        self.mounts = []
        
    def enumerate_all(self):
        """Run all Docker enumeration"""
        self.check_in_container()
        self.check_socket_access()
        
        if self.socket_access:
            self.get_containers()
            self.get_images()
            self.get_volumes()
            self.get_networks()
        
        if self.in_container:
            self.check_privileged()
            self.get_capabilities()
            self.get_mounts()
            self.check_escape_vectors()
        
        return {
            'in_container': self.in_container,
            'socket_access': self.socket_access,
            'privileged': self.privileged,
            'containers': self.containers,
            'images': self.images,
            'volumes': self.volumes,
            'networks': self.networks,
            'capabilities': self.capabilities,
            'mounts': self.mounts,
            'escape_vectors': getattr(self, 'escape_vectors', [])
        }
    
    def check_in_container(self):
        """Detect if running inside a container"""
        if Path('/.dockerenv').exists():
            self.in_container = True
            return True

        if _IS_MACOS:
            # macOS: check env var and process tree only
            if os.environ.get('container'):
                self.in_container = True
                return True
            return False

        # Linux: check cgroup
        try:
            with open('/proc/1/cgroup') as f:
                content = f.read()
                if 'docker' in content or 'kubepods' in content:
                    self.in_container = True
                    return True
        except:
            pass

        try:
            hostname = os.uname().nodename
            if len(hostname) == 12 and all(c in '0123456789abcdef' for c in hostname):
                self.in_container = True
                return True
        except:
            pass

        return False
    
    def check_socket_access(self):
        """Check if Docker socket is accessible"""
        socket_paths = [
            '/var/run/docker.sock',
            '/run/docker.sock',
            '/var/lib/docker.sock'
        ]
        
        for sock in socket_paths:
            if Path(sock).exists():
                # Check if readable
                try:
                    result = subprocess.run(
                        ['docker', 'ps'],
                        capture_output=True,
                        timeout=2
                    )
                    if result.returncode == 0:
                        self.socket_access = True
                        return True
                except:
                    pass
        
        return False
    
    def get_containers(self):
        """List Docker containers"""
        try:
            result = subprocess.run(
                ['docker', 'ps', '-a', '--format', '{{json .}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            container = json.loads(line)
                            self.containers.append({
                                'id': container.get('ID', '')[:12],
                                'name': container.get('Names', ''),
                                'image': container.get('Image', ''),
                                'status': container.get('Status', ''),
                                'ports': container.get('Ports', '')
                            })
                        except:
                            pass
        except:
            pass
        
        return self.containers
    
    def get_images(self):
        """List Docker images"""
        try:
            result = subprocess.run(
                ['docker', 'images', '--format', '{{json .}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            image = json.loads(line)
                            self.images.append({
                                'repository': image.get('Repository', ''),
                                'tag': image.get('Tag', ''),
                                'id': image.get('ID', ''),
                                'size': image.get('Size', '')
                            })
                        except:
                            pass
        except:
            pass
        
        return self.images
    
    def get_volumes(self):
        """List Docker volumes"""
        try:
            result = subprocess.run(
                ['docker', 'volume', 'ls', '--format', '{{json .}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            volume = json.loads(line)
                            self.volumes.append({
                                'name': volume.get('Name', ''),
                                'driver': volume.get('Driver', '')
                            })
                        except:
                            pass
        except:
            pass
        
        return self.volumes
    
    def get_networks(self):
        """List Docker networks"""
        try:
            result = subprocess.run(
                ['docker', 'network', 'ls', '--format', '{{json .}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            network = json.loads(line)
                            self.networks.append({
                                'id': network.get('ID', '')[:12],
                                'name': network.get('Name', ''),
                                'driver': network.get('Driver', '')
                            })
                        except:
                            pass
        except:
            pass
        
        return self.networks
    
    def check_privileged(self):
        """Check if container is running in privileged mode"""
        if _IS_MACOS:
            return False  # macOS doesn't have Linux capability model
        try:
            with open('/proc/self/status') as f:
                for line in f:
                    if line.startswith('CapEff:'):
                        cap_eff = int(line.split()[1], 16)
                        if cap_eff == 0x3fffffffff or cap_eff == 0x1ffffffffff:
                            self.privileged = True
                            return True
        except:
            pass
        return False
    
    def get_capabilities(self):
        """Get current capabilities"""
        if _IS_MACOS:
            self.capabilities = ['N/A (macOS — no Linux capability model)']
            return self.capabilities
        try:
            result = subprocess.run(
                ['capsh', '--print'], capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Current:' in line:
                        caps = line.split('Current:')[1].strip()
                        self.capabilities = caps.split(',')
        except:
            try:
                with open('/proc/self/status') as f:
                    for line in f:
                        if line.startswith('CapEff:'):
                            cap_hex = line.split()[1]
                            self.capabilities.append(f'CapEff: 0x{cap_hex}')
            except:
                pass
        return self.capabilities
    
    def get_mounts(self):
        """Get container mounts"""
        if _IS_MACOS:
            return self._get_mounts_macos()
        try:
            with open('/proc/self/mountinfo') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 5:
                        mount_point = parts[4]
                        mount_source = parts[3] if len(parts) > 3 else ''
                        if any(x in mount_point for x in ['/host', '/proc', '/sys', '/var/run/docker.sock']):
                            self.mounts.append({
                                'source': mount_source,
                                'target': mount_point,
                                'interesting': True
                            })
        except:
            pass
        return self.mounts

    def _get_mounts_macos(self):
        try:
            result = subprocess.run(
                ['mount'], capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.strip().split('\n'):
                if any(x in line for x in ['/host', '/var/run/docker.sock']):
                    parts = line.split()
                    mount_point = parts[2] if len(parts) >= 3 else line
                    self.mounts.append({'source': parts[0] if parts else '', 'target': mount_point, 'interesting': True})
        except:
            pass
        return self.mounts
    
    def check_escape_vectors(self):
        """Check for container escape vectors"""
        self.escape_vectors = []
        
        # Docker socket mounted
        if Path('/var/run/docker.sock').exists():
            self.escape_vectors.append({
                'type': 'Docker Socket Mounted',
                'severity': 'CRITICAL',
                'description': 'Docker socket accessible from container',
                'exploit': 'docker run -v /:/host -it alpine chroot /host'
            })
        
        # Privileged mode
        if self.privileged:
            self.escape_vectors.append({
                'type': 'Privileged Container',
                'severity': 'CRITICAL',
                'description': 'Container running with --privileged flag',
                'exploit': 'Full host access via /dev, /proc, /sys'
            })
        
        # Host PID namespace (Linux only)
        if _IS_LINUX:
            try:
                with open('/proc/1/cgroup') as f:
                    if 'docker' not in f.read():
                        self.escape_vectors.append({
                            'type': 'Host PID Namespace',
                            'severity': 'HIGH',
                            'description': 'Sharing host PID namespace',
                            'exploit': 'Can see and interact with host processes'
                        })
            except:
                pass
        
        # CAP_SYS_ADMIN
        if 'cap_sys_admin' in str(self.capabilities).lower():
            self.escape_vectors.append({
                'type': 'CAP_SYS_ADMIN',
                'severity': 'HIGH',
                'description': 'Container has CAP_SYS_ADMIN capability',
                'exploit': 'Mount host filesystem, load kernel modules'
            })
        
        return self.escape_vectors
    
    def report(self):
        """Generate human-readable report"""
        lines = []
        lines.append("="*60)
        lines.append("DOCKER ENUMERATION")
        lines.append("="*60)
        
        lines.append(f"\nIn Container: {self.in_container}")
        lines.append(f"Socket Access: {self.socket_access}")
        
        if self.in_container:
            lines.append(f"Privileged: {self.privileged}")
            
            if self.capabilities:
                lines.append(f"\nCapabilities: {len(self.capabilities)}")
                for cap in self.capabilities[:10]:
                    lines.append(f"  {cap}")
            
            if self.mounts:
                interesting = [m for m in self.mounts if m.get('interesting')]
                if interesting:
                    lines.append(f"\nInteresting Mounts: {len(interesting)}")
                    for mount in interesting:
                        lines.append(f"  {mount['target']}")
            
            if hasattr(self, 'escape_vectors') and self.escape_vectors:
                lines.append(f"\nEscape Vectors: {len(self.escape_vectors)}")
                for vec in self.escape_vectors:
                    lines.append(f"  [{vec['severity']}] {vec['type']}")
                    lines.append(f"    {vec['description']}")
        
        if self.socket_access:
            lines.append(f"\nContainers: {len(self.containers)}")
            for container in self.containers[:5]:
                lines.append(f"  {container['id']} {container['name']} ({container['status']})")
            
            lines.append(f"\nImages: {len(self.images)}")
            for image in self.images[:5]:
                lines.append(f"  {image['repository']}:{image['tag']}")
            
            lines.append(f"\nVolumes: {len(self.volumes)}")
            lines.append(f"Networks: {len(self.networks)}")
        
        return "\n".join(lines)

if __name__ == '__main__':
    enum = DockerEnumerator()
    enum.enumerate_all()
    print(enum.report())
