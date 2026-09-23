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
import re
import socket
import ssl
import urllib.request
import urllib.error
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

        # Daemon API reachability checks (always run — no socket needed)
        daemon_findings = self.probe_docker_daemon_api()

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

        # Per-container and per-image checks (require socket access)
        priv_findings = []
        port_findings = []
        env_findings = []
        layer_findings = []
        if self.socket_access:
            priv_findings = self.check_privileged_containers()
            port_findings = self.check_exposed_ports()
            env_findings = self.check_env_variable_secrets()
            layer_findings = self.check_image_for_sensitive_layers()

        # Cache for report()
        self._daemon_findings_cache = daemon_findings
        self._priv_findings_cache = priv_findings
        self._port_findings_cache = port_findings
        self._env_findings_cache = env_findings
        self._layer_findings_cache = layer_findings

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
            'escape_vectors': getattr(self, 'escape_vectors', []),
            'daemon_api_findings': daemon_findings,
            'privileged_container_findings': priv_findings,
            'exposed_port_findings': port_findings,
            'env_secret_findings': env_findings,
            'image_layer_findings': layer_findings,
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
    
    # ------------------------------------------------------------------
    # New enumeration methods
    # ------------------------------------------------------------------

    def probe_docker_daemon_api(self, host='localhost', port=2375):
        """Probe TCP Docker daemon API on port 2375 (unauth) and 2376 (TLS).

        Returns a list of finding dicts with keys: severity, title, detail.
        """
        findings = []

        # --- Port 2375: plain HTTP, unauthenticated ---
        url = f'http://{host}:{port}/version'
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'docker/cli'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    try:
                        data = json.loads(resp.read().decode('utf-8', errors='replace'))
                    except Exception:
                        data = {}
                    detail_parts = []
                    for key in ('Version', 'APIVersion', 'Os', 'Arch'):
                        if key in data:
                            detail_parts.append(f'{key}={data[key]}')
                    detail = f'TCP {host}:{port} responded without authentication. ' + \
                             (', '.join(detail_parts) if detail_parts else 'No version info returned.')
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'Docker daemon API unauthenticated on TCP port',
                        'detail': detail,
                        'host': host,
                        'port': port,
                    })
        except urllib.error.URLError:
            pass
        except OSError:
            pass
        except Exception:
            pass

        # --- Port 2376: TLS, but we do not verify cert ---
        tls_port = 2376
        tls_url = f'https://{host}:{tls_port}/version'
        try:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(tls_url, headers={'User-Agent': 'docker/cli'})
            with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
                if resp.status == 200:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'Docker TLS API accessible (cert not verified)',
                        'detail': (
                            f'TCP {host}:{tls_port} responded to /version over TLS without '
                            'mutual-TLS enforcement — client certificate not required.'
                        ),
                        'host': host,
                        'port': tls_port,
                    })
        except urllib.error.URLError:
            pass
        except ssl.SSLError:
            pass
        except OSError:
            pass
        except Exception:
            pass

        return findings

    def check_privileged_containers(self):
        """Inspect running containers for privileged mode, dangerous caps, and risky mounts.

        Returns a list of finding dicts.
        """
        findings = []
        _DANGEROUS_CAPS = {
            'CAP_SYS_ADMIN', 'CAP_NET_ADMIN', 'CAP_SYS_PTRACE',
            'CAP_SYS_MODULE', 'CAP_DAC_READ_SEARCH',
        }
        _DANGEROUS_MOUNTS = {'/var/run/docker.sock', '/', '/etc'}

        # Get list of running container IDs
        try:
            id_result = subprocess.run(
                ['docker', 'ps', '-q'],
                capture_output=True, text=True, timeout=5
            )
            container_ids = [c for c in id_result.stdout.strip().split('\n') if c]
        except Exception:
            return findings

        if not container_ids:
            return findings

        try:
            inspect_result = subprocess.run(
                ['docker', 'inspect'] + container_ids,
                capture_output=True, text=True, timeout=10
            )
            if inspect_result.returncode != 0:
                return findings
            containers = json.loads(inspect_result.stdout)
        except Exception:
            return findings

        for c in containers:
            cid = c.get('Id', '')[:12]
            cname = (c.get('Name', '') or '').lstrip('/')
            hc = c.get('HostConfig', {})

            # Privileged flag
            if hc.get('Privileged', False):
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'Privileged container',
                    'detail': (
                        f'Container {cname} ({cid}) running with --privileged: '
                        'all Linux capabilities granted, full access to host devices and /sys/fs/cgroup.'
                    ),
                    'container': cname,
                    'container_id': cid,
                })

            # Dangerous capabilities
            cap_add = hc.get('CapAdd') or []
            for cap in cap_add:
                normalized = cap.upper() if not cap.upper().startswith('CAP_') else cap.upper()
                if not normalized.startswith('CAP_'):
                    normalized = 'CAP_' + normalized
                if normalized in _DANGEROUS_CAPS:
                    findings.append({
                        'severity': 'HIGH',
                        'title': f'Dangerous capability granted: {normalized}',
                        'detail': (
                            f'Container {cname} ({cid}) has {normalized} in CapAdd. '
                            'May allow kernel exploitation, ptrace-based escapes, or raw packet injection.'
                        ),
                        'container': cname,
                        'container_id': cid,
                        'capability': normalized,
                    })

            # Risky mounts
            mounts = c.get('Mounts', [])
            for mount in mounts:
                src = mount.get('Source', '')
                for dangerous in _DANGEROUS_MOUNTS:
                    if src == dangerous or src.startswith(dangerous + '/') or src.rstrip('/') == dangerous.rstrip('/'):
                        sev = 'CRITICAL'
                        title = f'Dangerous mount: {src} -> {mount.get("Destination", "?")}'
                        detail = (
                            f'Container {cname} ({cid}) mounts {src} at '
                            f'{mount.get("Destination", "?")}.'
                        )
                        if dangerous == '/var/run/docker.sock':
                            detail += ' Docker socket mount grants full Docker API access = host escape.'
                        elif dangerous == '/':
                            detail += ' Host root filesystem mounted — trivial host escape via chroot.'
                        elif dangerous == '/etc':
                            detail += ' /etc mount allows overwriting /etc/passwd, /etc/sudoers, or cron files.'
                        findings.append({
                            'severity': sev,
                            'title': title,
                            'detail': detail,
                            'container': cname,
                            'container_id': cid,
                            'mount_source': src,
                        })
                        break  # one finding per mount entry

        return findings

    def check_exposed_ports(self):
        """Check running containers for ports bound to 0.0.0.0 (all interfaces).

        Returns a list of finding dicts.
        """
        findings = []

        try:
            result = subprocess.run(
                ['docker', 'ps', '--format', '{{json .}}'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return findings
        except Exception:
            return findings

        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue

            cid = entry.get('ID', '')[:12]
            cname = entry.get('Names', '')
            ports_str = entry.get('Ports', '')

            # Ports field format examples:
            #   0.0.0.0:8080->80/tcp, :::8080->80/tcp
            #   127.0.0.1:8080->80/tcp
            for segment in ports_str.split(','):
                segment = segment.strip()
                if not segment:
                    continue
                # Match host-binding patterns
                m = re.match(r'^([\d.:]+):(\d+)->(\d+/\w+)$', segment)
                if m:
                    bind_addr = m.group(1)
                    host_port = m.group(2)
                    container_port = m.group(3)
                    if bind_addr in ('0.0.0.0', '::'):
                        findings.append({
                            'severity': 'MEDIUM',
                            'title': 'Container port exposed on all interfaces',
                            'detail': (
                                f'Container {cname} ({cid}) maps {container_port} to '
                                f'{bind_addr}:{host_port} — externally reachable. '
                                'Bind to 127.0.0.1 or use a reverse proxy.'
                            ),
                            'container': cname,
                            'container_id': cid,
                            'host_port': host_port,
                            'container_port': container_port,
                            'bind_address': bind_addr,
                        })

        return findings

    def check_env_variable_secrets(self):
        """Inspect running containers for secret-like environment variables.

        Returns a list of finding dicts with redacted values.
        """
        findings = []
        _SECRET_PATTERNS = re.compile(
            r'(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|API_KEY|AUTH)',
            re.IGNORECASE
        )

        try:
            id_result = subprocess.run(
                ['docker', 'ps', '-q'],
                capture_output=True, text=True, timeout=5
            )
            container_ids = [c for c in id_result.stdout.strip().split('\n') if c]
        except Exception:
            return findings

        if not container_ids:
            return findings

        try:
            inspect_result = subprocess.run(
                ['docker', 'inspect'] + container_ids,
                capture_output=True, text=True, timeout=10
            )
            if inspect_result.returncode != 0:
                return findings
            containers = json.loads(inspect_result.stdout)
        except Exception:
            return findings

        for c in containers:
            cid = c.get('Id', '')[:12]
            cname = (c.get('Name', '') or '').lstrip('/')
            env_list = (c.get('Config', {}) or {}).get('Env') or []
            for env_entry in env_list:
                if '=' not in env_entry:
                    continue
                var_name, _, var_value = env_entry.partition('=')
                if _SECRET_PATTERNS.search(var_name):
                    redacted = (var_value[:4] + '***') if len(var_value) > 4 else '***'
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': f'Secret-like env variable exposed: {var_name}',
                        'detail': (
                            f'Container {cname} ({cid}) has {var_name}={redacted} in environment. '
                            'Visible via `docker inspect`. Use Docker secrets or a vault instead.'
                        ),
                        'container': cname,
                        'container_id': cid,
                        'variable': var_name,
                        'value_redacted': redacted,
                    })

        return findings

    def check_image_for_sensitive_layers(self, image_id=None):
        """Scan image history for risky Dockerfile patterns in ADD/COPY/RUN layers.

        If image_id is None, scans all local images.
        Returns a list of finding dicts.
        """
        findings = []

        # Patterns that indicate risky layer content
        _RISKY_PATTERNS = [
            (re.compile(r'\bcurl\b|\bwget\b', re.IGNORECASE),
             'Remote download in RUN layer — content not pinned or verified.'),
            (re.compile(r'apt-get install(?!.*--no-install-recommends)', re.IGNORECASE),
             'apt-get install without --no-install-recommends — bloated image, wider attack surface.'),
            (re.compile(r'COPY\s+.*\.env\b', re.IGNORECASE),
             'COPY of .env file into image — secrets baked into layer.'),
            (re.compile(r'\bRUN\b.*echo\b.*(?:password|secret|token|key|credential)\b',
                        re.IGNORECASE),
             'Hardcoded secret string in RUN echo statement — visible in layer history.'),
            (re.compile(r'\bENV\b\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|API_KEY|AUTH)\w*\s*=',
                        re.IGNORECASE),
             'Secret-like value set via ENV instruction — persists in image metadata.'),
            (re.compile(r'ADD\s+https?://', re.IGNORECASE),
             'ADD from remote URL — fetched at build time without integrity verification.'),
        ]

        # Collect target image IDs
        if image_id is not None:
            image_ids = [image_id]
        else:
            try:
                result = subprocess.run(
                    ['docker', 'images', '-q'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode != 0:
                    return findings
                # deduplicate
                image_ids = list(dict.fromkeys(
                    i for i in result.stdout.strip().split('\n') if i
                ))
            except Exception:
                return findings

        for img in image_ids:
            try:
                hist_result = subprocess.run(
                    ['docker', 'history', '--no-trunc', '--format',
                     '{{.CreatedBy}}', img],
                    capture_output=True, text=True, timeout=10
                )
                if hist_result.returncode != 0:
                    continue
            except Exception:
                continue

            for layer_cmd in hist_result.stdout.strip().split('\n'):
                layer_cmd = layer_cmd.strip()
                if not layer_cmd:
                    continue
                for pattern, description in _RISKY_PATTERNS:
                    if pattern.search(layer_cmd):
                        # Truncate long commands for readability
                        cmd_snippet = layer_cmd[:120] + ('...' if len(layer_cmd) > 120 else '')
                        findings.append({
                            'severity': 'HIGH',
                            'title': f'Risky image layer pattern detected',
                            'detail': (
                                f'Image {img}: {description} '
                                f'Layer: {cmd_snippet}'
                            ),
                            'image_id': img,
                            'layer_snippet': cmd_snippet,
                            'pattern_description': description,
                        })
                        break  # one finding per layer line

        return findings

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

        # New findings sections
        def _print_findings(label, findings):
            if findings:
                lines.append(f"\n{label}: {len(findings)}")
                for f in findings:
                    lines.append(f"  [{f.get('severity','?')}] {f.get('title','')}")
                    lines.append(f"    {f.get('detail','')}")

        _print_findings("Daemon API Findings",
                        getattr(self, '_daemon_findings_cache', []))
        _print_findings("Privileged Container Findings",
                        getattr(self, '_priv_findings_cache', []))
        _print_findings("Exposed Port Findings",
                        getattr(self, '_port_findings_cache', []))
        _print_findings("Env Secret Findings",
                        getattr(self, '_env_findings_cache', []))
        _print_findings("Image Layer Findings",
                        getattr(self, '_layer_findings_cache', []))

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Standalone supply-chain / isolation functions (no third-party deps)
# ---------------------------------------------------------------------------

def check_container_isolation(host: str = "localhost", timeout: float = 5.0) -> list:
    """Check container isolation escape surface using local /proc entries."""
    import os
    import re as _re

    findings = []

    def _read(path: str) -> str:
        try:
            with open(path, "r", errors="replace") as fh:
                return fh.read()
        except Exception:
            return ""

    def _find(severity: str, title: str, detail: str):
        findings.append({"severity": severity, "title": title, "detail": detail,
                         "host": host, "port": 0})

    # 1. Detect if running inside a container
    cgroup = _read("/proc/1/cgroup")
    in_container = bool(_re.search(r"(docker|kubepods|containerd|lxc)", cgroup))
    if not in_container:
        _find("INFO", "NOT_IN_CONTAINER",
              "Process hierarchy shows no docker/kubepods cgroup — not running inside a container.")
        return findings  # remaining checks only meaningful inside a container

    # 2. CAP_SYS_ADMIN (bit 21) in effective capability set
    status = _read("/proc/self/status")
    cap_match = _re.search(r"^CapEff:\s+([0-9a-fA-F]+)", status, _re.MULTILINE)
    if cap_match:
        cap_eff = int(cap_match.group(1), 16)
        if cap_eff & (1 << 21):
            _find("CRITICAL", "CAP_SYS_ADMIN_IN_CONTAINER — escape possible",
                  "CapEff bit 21 (CAP_SYS_ADMIN) is set inside the container. "
                  "Attacker can mount filesystems or use userns to escape.")

    # 3. Docker socket bind-mounted
    mounts = _read("/proc/self/mounts")
    if "/var/run/docker.sock" in mounts:
        _find("CRITICAL", "DOCKER_SOCKET_MOUNTED — container escape",
              "/var/run/docker.sock is mounted inside the container. "
              "Full Docker daemon control = trivial host escape.")

    # 4. Host root mounted (overlay with lowerdir pointing to /)
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "overlay":
            opts = parts[3]
            if "lowerdir=/" in opts or "upperdir=/" in opts:
                _find("CRITICAL", "HOST_ROOT_MOUNTED",
                      f"Overlay mount with host-root lowerdir/upperdir detected: {opts[:120]}")
                break

    # 5. Shared PID namespace check
    try:
        init_pid_ns = os.readlink("/proc/1/ns/pid")
        self_pid_ns = os.readlink("/proc/self/ns/pid")
        if init_pid_ns == self_pid_ns:
            _find("CRITICAL", "SHARED_PID_NAMESPACE",
                  f"PID namespace inode matches host init ({init_pid_ns}). "
                  "Container shares host PID namespace — full process visibility.")
    except Exception:
        pass

    return findings


def check_image_security(registry_host: str, port: int = 443,
                         timeout: float = 5.0) -> list:
    """Check container image supply chain posture against an OCI/Docker registry."""
    import ssl
    import json
    import urllib.request
    import urllib.error

    findings = []

    def _find(severity: str, title: str, detail: str):
        findings.append({"severity": severity, "title": title, "detail": detail,
                         "host": registry_host, "port": port})

    use_tls = port == 443 or port == 5001
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{registry_host}:{port}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str, headers: dict | None = None) -> tuple[int, bytes]:
        url = f"{base}{path}"
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=ctx if use_tls else None) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            return 0, b""

    # 1. Anonymous pull / unauthenticated /v2/
    status, _ = _get("/v2/")
    if status == 200:
        _find("CRITICAL", "REGISTRY_ANONYMOUS_PULL",
              f"GET /v2/ returned 200 without credentials on {registry_host}:{port}. "
              "Registry allows unauthenticated access.")

    # 2. Catalog exposed
    status, body = _get("/v2/_catalog")
    if status == 200:
        _find("CRITICAL", "REGISTRY_CATALOG_EXPOSED — full image inventory",
              f"GET /v2/_catalog returned 200: full repository list accessible. "
              f"Body snippet: {body[:200]!r}")

    # 3. Sample a well-known repo for Notary/Cosign signature annotation
    sample_repos = ["library/alpine", "library/ubuntu", "alpine", "ubuntu"]
    for repo in sample_repos:
        for tag in ("latest", "3.18"):
            status, body = _get(
                f"/v2/{repo}/manifests/{tag}",
                {"Accept": "application/vnd.oci.image.manifest.v1+json"})
            if status == 200:
                try:
                    manifest = json.loads(body)
                    annotations = manifest.get("annotations") or {}
                    # Notary v2 signature annotation
                    if "io.cncf.notary.signature" not in annotations:
                        _find("HIGH", "IMAGE_NOT_SIGNED — supply chain risk",
                              f"Manifest {repo}:{tag} has no io.cncf.notary.signature "
                              "annotation. Image provenance cannot be verified.")
                    # Check referrers for SBOM / cosign signatures
                    digest_hdr = manifest.get("config", {}).get("digest", "")
                    if digest_hdr:
                        ref_status, ref_body = _get(f"/v2/{repo}/referrers/{digest_hdr}")
                        if ref_status == 200:
                            try:
                                referrers = json.loads(ref_body)
                                if not referrers.get("manifests"):
                                    _find("MEDIUM", "NO_IMAGE_ATTESTATIONS",
                                          f"No referrers (SBOM/signatures) for {repo}@{digest_hdr}.")
                            except Exception:
                                pass
                        else:
                            _find("MEDIUM", "NO_IMAGE_ATTESTATIONS",
                                  f"Referrers API returned {ref_status} for {repo}:{tag} — "
                                  "no SBOM or cosign signatures found.")
                except Exception:
                    pass
                break  # found a manifest; move to next repo
    return findings


def check_resource_quota_bypass(host: str, port: int = 443,
                                timeout: float = 5.0,
                                namespace: str = "default") -> list:
    """Check Kubernetes resource quota/LimitRange enforcement gaps."""
    import ssl
    import json
    import urllib.request
    import urllib.error

    findings = []

    def _find(severity: str, title: str, detail: str):
        findings.append({"severity": severity, "title": title, "detail": detail,
                         "host": host, "port": port})

    use_tls = port == 443 or port == 6443
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{host}:{port}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str) -> tuple[int, dict]:
        url = f"{base}{path}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=ctx if use_tls else None) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, {}
        except Exception:
            return 0, {}

    ns = namespace or "default"

    # 1. ResourceQuotas
    status, data = _get(f"/api/v1/namespaces/{ns}/resourcequotas")
    if status == 200:
        items = data.get("items", [])
        if not items:
            _find("HIGH", "NO_RESOURCE_QUOTAS — CPU/memory exhaustion possible",
                  f"Namespace '{ns}' has no ResourceQuota objects. "
                  "Tenants can consume unbounded CPU and memory.")

    # 2. LimitRanges
    status, data = _get(f"/api/v1/namespaces/{ns}/limitranges")
    if status == 200:
        items = data.get("items", [])
        if not items:
            _find("HIGH", "NO_LIMIT_RANGES — unlimited resource consumption",
                  f"Namespace '{ns}' has no LimitRange objects. "
                  "Containers have no default/max resource bounds.")

    # 3. Pods missing resource requests/limits
    status, data = _get("/api/v1/pods")
    if status == 200:
        pods_without_limits: list[str] = []
        for pod in data.get("items", []):
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            pod_ns = pod.get("metadata", {}).get("namespace", "unknown")
            containers = pod.get("spec", {}).get("containers", [])
            for c in containers:
                resources = c.get("resources", {})
                requests = resources.get("requests")
                limits = resources.get("limits")
                if not requests or not limits:
                    pods_without_limits.append(f"{pod_ns}/{pod_name}/{c.get('name','?')}")
                    break
        if pods_without_limits:
            sample = pods_without_limits[:10]
            _find("MEDIUM", "PODS_WITHOUT_RESOURCE_LIMITS",
                  f"{len(pods_without_limits)} pod(s) lack resources.requests or .limits. "
                  f"Sample: {', '.join(sample)}")

    return findings


def check_dependency_confusion_indicators(registry_host: str, port: int = 443,
                                          timeout: float = 5.0) -> list:
    """Check for dependency/namespace confusion attack surface in a container registry."""
    import ssl
    import json
    import urllib.request
    import urllib.error

    COMMON_PUBLIC_PACKAGES = [
        "express", "lodash", "react", "numpy", "requests",
        "flask", "django", "axios", "moment", "chalk",
    ]

    findings = []

    def _find(severity: str, title: str, detail: str):
        findings.append({"severity": severity, "title": title, "detail": detail,
                         "host": registry_host, "port": port})

    use_tls = port == 443 or port == 5001
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{registry_host}:{port}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str) -> tuple[int, bytes]:
        url = f"{base}{path}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=ctx if use_tls else None) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            return 0, b""

    # 1. Full catalog — look for internal-prefixed repos exposed publicly
    status, body = _get("/v2/_catalog")
    repos: list[str] = []
    if status == 200:
        try:
            data = json.loads(body)
            repos = data.get("repositories", [])
        except Exception:
            repos = []

        internal_exposed = [r for r in repos
                            if r.startswith("internal-") or r.startswith("private-")]
        if internal_exposed:
            _find("HIGH", "INTERNAL_REPOS_PUBLICLY_LISTED",
                  f"Registry catalog exposes {len(internal_exposed)} internal/private repo(s) "
                  f"without authentication: {', '.join(internal_exposed[:10])}")

        # 2. Common package names mirrored in private registry (confusion risk)
        matched = [r for r in repos
                   if any(pkg in r.split("/")[-1] for pkg in COMMON_PUBLIC_PACKAGES)]
        if matched:
            _find("MEDIUM", "COMMON_PACKAGE_NAME_IN_REGISTRY — dependency confusion risk",
                  f"Private registry contains repo name(s) matching well-known public packages: "
                  f"{', '.join(matched[:10])}. Dependency confusion attack possible if resolver "
                  "prefers private registry without version pinning.")

    # 3. Direct probe for each common package name
    for pkg in COMMON_PUBLIC_PACKAGES:
        s, b = _get(f"/v2/{pkg}/tags/list")
        if s == 200:
            _find("HIGH", "DEPENDENCY_CONFUSION_PACKAGE_EXISTS",
                  f"Repository '{pkg}' exists in private registry and matches a well-known "
                  f"npm/PyPI package name. Clients that prefer this registry will pull the "
                  "private image instead of the public package — supply chain confusion risk.")

    return findings


def check_k8s_network_policy_gaps(host: str, port: int = 8001,
                                  timeout: float = 5.0) -> list:
    """Check Kubernetes network policy gaps via unauthenticated API probes.

    Synthesized from: Kubernetes Up and Running 3e, Chapter 19 (Network Policy)
    and Chapter 14 (RBAC). Probes the API server (or kubectl proxy at port 8001)
    for missing or sparse NetworkPolicy objects and unauth namespace/pod exposure.
    NetworkPolicy resources require a CNI plugin (Calico, Cilium, Weave Net);
    the API alone does not enforce isolation without a compatible network plugin.
    """
    import ssl
    import json
    import urllib.request
    import urllib.error

    findings = []

    def _find(severity: str, title: str, detail: str):
        findings.append({"severity": severity, "title": title, "detail": detail,
                         "host": host, "port": port})

    use_tls = port in (443, 6443)
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{host}:{port}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str) -> tuple[int, dict]:
        url = f"{base}{path}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(
                req, timeout=timeout,
                context=ctx if use_tls else None
            ) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, {}
        except Exception:
            return 0, {}

    # 1. Unauthenticated pod list — direct exposure of running workloads
    status, data = _get("/api/v1/namespaces/default/pods")
    if status == 200 and "items" in data:
        pod_count = len(data.get("items", []))
        _find("CRITICAL", "K8S_POD_LIST_UNAUTH",
              f"Kubernetes API returned pod list for namespace 'default' without "
              f"authentication ({pod_count} pod(s) visible). Anonymous read access "
              "to workload state violates least-privilege; an attacker can enumerate "
              "running containers, image names, and environment variable references.")

    # 2. Network policies — cluster-wide presence check
    status, data = _get("/apis/networking.k8s.io/v1/networkpolicies")
    if status == 200:
        policies = data.get("items", [])
        if not policies:
            _find("HIGH", "NO_NETWORK_POLICIES — unrestricted pod-to-pod traffic",
                  "No NetworkPolicy objects found across all namespaces. Without network "
                  "policies every pod can reach every other pod regardless of namespace. "
                  "A CNI plugin (Calico, Cilium, Weave Net) must be installed AND policies "
                  "created; the NetworkPolicy API alone does not enforce isolation.")
        else:
            # 3. Sparse policy check — fewer than 2 policies for a cluster with >10 pods
            total_pods_status, total_pods_data = _get("/api/v1/pods")
            total_pods = 0
            if total_pods_status == 200:
                total_pods = len(total_pods_data.get("items", []))
            if total_pods > 10 and len(policies) < 2:
                _find("HIGH", "SPARSE_NETWORK_POLICIES",
                      f"Cluster has {total_pods} pods but only {len(policies)} NetworkPolicy "
                      "object(s). Sparse policy coverage leaves most pod-to-pod paths "
                      "unrestricted. Minimum baseline: default-deny ingress+egress per namespace "
                      "with explicit allow rules for required service communication.")

    # 4. Namespace list — unauthenticated cluster topology disclosure
    status, data = _get("/api/v1/namespaces")
    if status == 200 and "items" in data:
        ns_names = [
            ns.get("metadata", {}).get("name", "?")
            for ns in data.get("items", [])
        ]
        _find("HIGH", "NAMESPACE_LIST_UNAUTH",
              f"Kubernetes API returned namespace list without authentication "
              f"({len(ns_names)} namespace(s): {', '.join(ns_names[:15])}). "
              "Cluster topology disclosure enables targeted lateral movement; "
              "RBAC anonymous binding should be audited and revoked.")

    return findings


def check_pod_security_admission(host: str, port: int = 8001,
                                 timeout: float = 5.0) -> list:
    """Check Kubernetes Pod Security Admission configuration and host-namespace escapes.

    Synthesized from: Kubernetes Up and Running 3e, Chapter 19 (Pod Security,
    SecurityContext, hostNetwork/hostPID) and Chapter 20 (policy and governance).
    Probes for missing PSA enforce labels on namespaces, legacy PSP API exposure,
    and pods running with host network or PID namespace sharing — both documented
    container-escape vectors when combined with node-level process or network access.
    """
    import ssl
    import json
    import urllib.request
    import urllib.error

    findings = []

    def _find(severity: str, title: str, detail: str):
        findings.append({"severity": severity, "title": title, "detail": detail,
                         "host": host, "port": port})

    use_tls = port in (443, 6443)
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{host}:{port}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str) -> tuple[int, dict]:
        url = f"{base}{path}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(
                req, timeout=timeout,
                context=ctx if use_tls else None
            ) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, {}
        except Exception:
            return 0, {}

    # 1. Pod Security Admission labels on namespaces
    status, data = _get("/api/v1/namespaces")
    if status == 200:
        psa_label = "pod-security.kubernetes.io/enforce"
        unlabeled: list[str] = []
        for ns in data.get("items", []):
            ns_name = ns.get("metadata", {}).get("name", "?")
            labels = ns.get("metadata", {}).get("labels", {})
            if psa_label not in labels:
                unlabeled.append(ns_name)
        if unlabeled:
            _find("HIGH", "NO_PSA_LABELS — Pod Security Admission not configured",
                  f"{len(unlabeled)} namespace(s) lack the "
                  f"'{psa_label}' label required for Pod Security Admission enforcement: "
                  f"{', '.join(unlabeled[:15])}. Without this label the admission controller "
                  "applies no security profile (privileged default), allowing unrestricted "
                  "SecurityContext values including privileged containers and host mounts.")

    # 2. Legacy PodSecurityPolicy API — deprecated in 1.21, removed in 1.25
    status, _ = _get("/apis/policy/v1beta1/podsecuritypolicies")
    if status == 200:
        _find("MEDIUM", "PSP_API_ENABLED — legacy policy, evaluate migration",
              "The deprecated PodSecurityPolicy API (policy/v1beta1/podsecuritypolicies) "
              "is responding. PSP was removed in Kubernetes v1.25. Its presence indicates "
              "a pre-1.25 cluster or a cluster with CRD shims; PSP semantics are inconsistent "
              "and the API has known bypasses. Migrate to Pod Security Admission + OPA/Gatekeeper.")

    # 3. Pods with hostNetwork=true — break out of pod network namespace
    status, data = _get("/api/v1/pods?fieldSelector=spec.hostNetwork%3Dtrue")
    if status == 200:
        items = data.get("items", [])
        if items:
            pod_ids = [
                f"{p.get('metadata', {}).get('namespace', '?')}/"
                f"{p.get('metadata', {}).get('name', '?')}"
                for p in items
            ]
            _find("HIGH", "HOST_NETWORK_PODS — network namespace breakout",
                  f"{len(items)} pod(s) running with spec.hostNetwork=true: "
                  f"{', '.join(pod_ids[:10])}. These pods share the node's network "
                  "namespace and can sniff node-level traffic, bind host ports, and reach "
                  "services that are otherwise inaccessible from inside the pod network.")

    # 4. Pods with hostPID=true — escape to node process namespace
    status, data = _get("/api/v1/pods?fieldSelector=spec.hostPID%3Dtrue")
    if status == 200:
        items = data.get("items", [])
        if items:
            pod_ids = [
                f"{p.get('metadata', {}).get('namespace', '?')}/"
                f"{p.get('metadata', {}).get('name', '?')}"
                for p in items
            ]
            _find("HIGH", "HOST_PID_PODS — process namespace escape",
                  f"{len(items)} pod(s) running with spec.hostPID=true: "
                  f"{', '.join(pod_ids[:10])}. Sharing the host PID namespace allows "
                  "the pod to see and signal all processes on the node, inspect /proc/<pid>/environ "
                  "for secrets, and ptrace node-level processes — direct host compromise path.")

    return findings


def check_service_account_token_exposure(host: str, port: int = 8001,
                                         timeout: float = 5.0) -> list:
    """Check Kubernetes service account token exposure via unauthenticated API probes.

    Synthesized from: Kubernetes Up and Running 3e, Chapter 14 (RBAC — service
    account identities, token projection, system:unauthenticated group) and
    Chapter 19 (securing applications). Service account tokens are cluster
    credentials; unauthenticated access to the SA list or token secrets gives
    an attacker a direct path to authenticated API calls within the cluster.
    In-pod token exposure (projected volume at the well-known path) enables
    privilege escalation from a compromised container to the cluster API.
    """
    import ssl
    import json
    import os
    import urllib.request
    import urllib.error

    findings = []

    def _find(severity: str, title: str, detail: str):
        findings.append({"severity": severity, "title": title, "detail": detail,
                         "host": host, "port": port})

    use_tls = port in (443, 6443)
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{host}:{port}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str) -> tuple[int, dict]:
        url = f"{base}{path}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(
                req, timeout=timeout,
                context=ctx if use_tls else None
            ) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read())
            except Exception:
                body = {}
            return e.code, body
        except Exception:
            return 0, {}

    # 1. Service account list — unauthenticated enumeration of all identities
    status, data = _get("/api/v1/serviceaccounts")
    if status == 200 and data.get("kind") in ("ServiceAccountList", "List"):
        items = data.get("items", [])
        sa_ids = [
            f"{sa.get('metadata', {}).get('namespace', '?')}/"
            f"{sa.get('metadata', {}).get('name', '?')}"
            for sa in items
        ]
        _find("CRITICAL", "SERVICE_ACCOUNT_LIST_UNAUTH",
              f"Kubernetes API returned full service account list without authentication "
              f"({len(items)} service account(s): {', '.join(sa_ids[:15])}). "
              "Service account identities map directly to RBAC permissions; enumeration "
              "discloses the complete cluster identity surface. Per K8s RBAC design, "
              "anonymous requests should be associated with system:unauthenticated with "
              "no list rights on service accounts. Revoke the anonymous ClusterRoleBinding "
              "or set --anonymous-auth=false on the API server.")

    # 2. Default service account token — direct credential retrieval
    status, data = _get("/api/v1/namespaces/default/serviceaccounts/default/token")
    if status == 200 and ("token" in data or data.get("kind") == "TokenRequest"):
        token_preview = str(data.get("status", {}).get("token", ""))[:32]
        _find("CRITICAL", "DEFAULT_SA_TOKEN_UNAUTH — cluster access credential exposed",
              "Kubernetes API returned a token for the default service account in the "
              "default namespace without authentication. This token can be used immediately "
              "to make authenticated API calls with whatever RBAC permissions are bound to "
              f"default/default. Token prefix (first 32 chars): '{token_preview}...'. "
              "Rotate the token, audit ClusterRoleBindings referencing system:unauthenticated, "
              "and enable --anonymous-auth=false. In-cluster workloads should use projected "
              "service account tokens with bounded TTLs (TokenRequest API).")

    # 3. Service account token secrets — bulk credential store exposure
    status, data = _get(
        "/api/v1/secrets"
        "?fieldSelector=type%3Dkubernetes.io%2Fservice-account-token"
    )
    if status == 200 and data.get("kind") in ("SecretList", "List"):
        items = data.get("items", [])
        if items:
            secret_ids = [
                f"{s.get('metadata', {}).get('namespace', '?')}/"
                f"{s.get('metadata', {}).get('name', '?')}"
                for s in items
            ]
            _find("CRITICAL", "SA_TOKEN_SECRETS_UNAUTH",
                  f"Kubernetes API returned {len(items)} service-account-token Secret(s) "
                  f"without authentication: {', '.join(secret_ids[:15])}. "
                  "Legacy static SA tokens (created automatically before K8s 1.24) stored "
                  "as Secrets do not expire; unauthenticated reads of this endpoint yields "
                  "long-lived cluster credentials. Migrate to TokenRequest projected volumes "
                  "with short TTLs and delete legacy auto-created token Secrets.")

    # 4. In-pod service account token — mounted credential readable from container
    sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    try:
        if os.path.isfile(sa_token_path) and os.access(sa_token_path, os.R_OK):
            with open(sa_token_path, "r") as fh:
                token_data = fh.read(64)
            _find("HIGH", "IN_POD_SA_TOKEN_READABLE",
                  f"In-pod service account token is readable at '{sa_token_path}'. "
                  f"Token prefix (first 64 chars): '{token_data.strip()[:64]}...'. "
                  "This confirms execution inside a Kubernetes pod. The mounted token "
                  "grants whatever RBAC permissions are bound to this pod's service account. "
                  "Verify the bound service account follows least-privilege; consider "
                  "automountServiceAccountToken: false on pods that do not call the K8s API, "
                  "and use projected tokens with bounded TTLs for those that do.")
    except (OSError, PermissionError):
        pass

    return findings


def check_opa_gatekeeper_policy_gaps(host: str, port: int = 8001,
                                     timeout: float = 5.0) -> list:
    """Check OPA/Gatekeeper policy enforcement gaps via unauthenticated API probes.

    Synthesized from: Kubernetes Up and Running 3e, Chapter 20 (Policy and
    Governance — Gatekeeper, OPA, ConstraintTemplates, admission webhooks,
    ValidatingWebhookConfiguration, MutatingWebhookConfiguration, resource
    quotas, audit). Absent Gatekeeper CRDs mean no server-side policy engine;
    absent validating webhooks mean admission-controller coverage is incomplete;
    suspicious mutating webhooks are a supply-chain or persistence vector because
    they can rewrite every CREATE/UPDATE request before storage.
    """
    import ssl
    import json
    import urllib.request
    import urllib.error

    findings = []

    def _find(severity: str, title: str, detail: str):
        findings.append({"severity": severity, "title": title, "detail": detail,
                         "host": host, "port": port})

    use_tls = port in (443, 6443)
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{host}:{port}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str) -> tuple[int, dict]:
        url = f"{base}{path}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(
                req, timeout=timeout,
                context=ctx if use_tls else None
            ) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read())
            except Exception:
                body = {}
            return e.code, body
        except Exception:
            return 0, {}

    # 1. Gatekeeper CRD presence — absence = no OPA policy engine
    status, data = _get("/apis/constraints.gatekeeper.sh/v1beta1")
    k8s_reachable = status in (200, 403, 401)
    if status == 0:
        # API server unreachable — remaining checks are moot
        return findings
    if status not in (200,):
        # 404 or similar: Gatekeeper API group absent
        _find("HIGH", "NO_GATEKEEPER_INSTALLED — no policy enforcement",
              "The Gatekeeper API group 'constraints.gatekeeper.sh/v1beta1' is not "
              f"registered on this cluster (HTTP {status}). Without OPA/Gatekeeper there "
              "is no server-side policy engine to enforce organizational constraints such as "
              "allowed container registries, mandatory resource limits, required labels, or "
              "unique ingress hostnames. PodSecurityPolicy was removed in K8s 1.25; "
              "Pod Security Admission is namespace-scoped and does not cover custom policy. "
              "Install Gatekeeper and deploy ConstraintTemplates + Constraints before "
              "workloads reach production namespaces.")
    else:
        # Gatekeeper present — check if any constraint templates are actually defined
        ct_status, ct_data = _get("/apis/templates.gatekeeper.sh/v1beta1/constrainttemplates")
        if ct_status == 200:
            templates = ct_data.get("items", [])
            if not templates:
                _find("HIGH", "GATEKEEPER_NO_CONSTRAINT_TEMPLATES — policy engine idle",
                      "Gatekeeper is installed but no ConstraintTemplates are defined. "
                      "Gatekeeper enforces policy only when ConstraintTemplates (Rego policy "
                      "definitions) and their corresponding Constraints (parameterized instances) "
                      "are both present. An empty template set means the admission webhook "
                      "accepts all resources unconditionally. Deploy templates for at minimum: "
                      "allowed registries, required resource limits, required labels, and "
                      "container privilege restrictions.")

    # 2. Resource quotas — absence enables noisy-neighbor resource exhaustion
    # Probe /api/v1/pods to confirm API reachability (even 403 is sufficient)
    pods_status, _ = _get("/api/v1/pods")
    if pods_status in (200, 403, 401):
        rq_status, rq_data = _get("/api/v1/resourcequotas")
        if rq_status == 200:
            quotas = rq_data.get("items", [])
            if not quotas:
                _find("HIGH", "NO_RESOURCE_QUOTAS — noisy neighbor attacks possible",
                      "No ResourceQuota objects found across any namespace. Without quotas "
                      "any tenant or compromised workload can exhaust cluster CPU, memory, "
                      "and object-count resources (pods, services, secrets) causing denial of "
                      "service to all other tenants. Apply ResourceQuota and LimitRange "
                      "objects to every tenant namespace as a baseline multi-tenancy control.")
        elif rq_status == 200 and rq_data.get("items"):
            # Quotas present — check for namespaces without quota coverage
            ns_status, ns_data = _get("/api/v1/namespaces")
            if ns_status == 200:
                covered_ns = {
                    q.get("metadata", {}).get("namespace")
                    for q in rq_data.get("items", [])
                }
                system_ns = {"kube-system", "kube-public", "kube-node-lease"}
                uncovered = [
                    ns.get("metadata", {}).get("name", "?")
                    for ns in ns_data.get("items", [])
                    if ns.get("metadata", {}).get("name") not in covered_ns
                    and ns.get("metadata", {}).get("name") not in system_ns
                ]
                if uncovered:
                    _find("MEDIUM", "NAMESPACES_WITHOUT_RESOURCE_QUOTAS",
                          f"{len(uncovered)} namespace(s) have no ResourceQuota: "
                          f"{', '.join(uncovered[:15])}. Partial quota coverage leaves "
                          "uncovered namespaces open to resource exhaustion.")

    # 3. Validating webhooks — absence means admission control gap
    vwh_status, vwh_data = _get(
        "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations"
    )
    if vwh_status == 200:
        webhooks = vwh_data.get("items", [])
        if not webhooks:
            _find("HIGH", "NO_VALIDATING_WEBHOOKS — admission control gap",
                  "No ValidatingWebhookConfiguration objects are registered. Validating "
                  "admission webhooks are the extension point for server-side policy engines "
                  "(Gatekeeper, Kyverno, custom validators). Their absence means all resource "
                  "CREATE and UPDATE operations reach storage without any external validation "
                  "beyond built-in API server checks. This gap allows noncompliant resources "
                  "(missing labels, forbidden registries, excessive privileges) to persist "
                  "undetected until manual audit.")

    # 4. Mutating webhooks — unexpected endpoints are a persistence/supply-chain vector
    mwh_status, mwh_data = _get(
        "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations"
    )
    if mwh_status == 200:
        known_system_prefixes = (
            "gatekeeper", "kyverno", "istio", "linkerd", "cert-manager",
            "vault", "rancher", "openshift", "datadoghq", "sidecar-injector",
        )
        for wh_config in mwh_data.get("items", []):
            config_name = wh_config.get("metadata", {}).get("name", "")
            for webhook in wh_config.get("webhooks", []):
                wh_name = webhook.get("name", "")
                client_cfg = webhook.get("clientConfig", {})
                # Webhooks calling an external URL (not in-cluster service) are suspicious
                url = client_cfg.get("url", "")
                svc = client_cfg.get("service", {})
                svc_ns = svc.get("namespace", "")
                svc_name = svc.get("name", "")
                is_known = any(
                    p in config_name.lower() or p in wh_name.lower()
                    or p in svc_name.lower()
                    for p in known_system_prefixes
                )
                if url and not is_known:
                    _find("HIGH", "SUSPICIOUS_MUTATING_WEBHOOK",
                          f"MutatingWebhookConfiguration '{config_name}' webhook '{wh_name}' "
                          f"routes admission requests to external URL '{url}'. Mutating "
                          "webhooks intercept every CREATE/UPDATE before storage and can "
                          "silently rewrite pod specs (inject containers, alter images, "
                          "strip security contexts). An external URL is not a standard "
                          "in-cluster pattern and may indicate supply-chain compromise or "
                          "a persistence implant. Audit the webhook endpoint, its operator, "
                          "and review admission logs for unexpected mutations.")
                elif svc_ns and svc_ns not in (
                    "gatekeeper-system", "kyverno", "istio-system", "cert-manager",
                    "kube-system", "linkerd", "cattle-system",
                ) and not is_known:
                    _find("MEDIUM", "UNEXPECTED_MUTATING_WEBHOOK_NAMESPACE",
                          f"MutatingWebhookConfiguration '{config_name}' webhook '{wh_name}' "
                          f"routes to service '{svc_name}' in namespace '{svc_ns}', which is "
                          "not a recognized system namespace for a standard admission controller. "
                          "Verify this webhook is intentional and audit its mutation logic.")

    return findings


def check_k8s_secret_exposure(host: str, port: int = 8001, timeout: float = 5.0) -> list:
    """Probe unauthenticated Kubernetes API secret endpoints.

    Targets the kube-apiserver proxy port (default 8001 / kubectl proxy) or a
    directly-exposed apiserver.  Checks cluster-wide secret list, default
    namespace secrets, and kube-system secrets, then counts base64-encoded
    data fields to confirm read access to secret payloads.

    Returns a list of finding dicts: {severity, title, detail, host, port}.
    """
    import urllib.request
    import ssl
    import json

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    findings = []
    base = f"https://{host}:{port}"

    def _req(path):
        url = base + path
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    raw = resp.read()
                    try:
                        return 200, json.loads(raw)
                    except Exception:
                        return 200, {}
                return resp.status, {}
        except urllib.error.HTTPError as e:
            return e.code, {}
        except Exception:
            return None, {}

    # --- cluster-wide secret list ---
    status, body = _req("/api/v1/secrets")
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "K8S_SECRETS_LIST_UNAUTH",
            "detail": "All Kubernetes secrets enumerable without auth via GET /api/v1/secrets",
            "host": host,
            "port": port,
        })

    # --- default namespace secrets ---
    status, body = _req("/api/v1/namespaces/default/secrets")
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "DEFAULT_NAMESPACE_SECRETS_UNAUTH",
            "detail": "Secrets in the default namespace readable without auth via GET /api/v1/namespaces/default/secrets",
            "host": host,
            "port": port,
        })

    # --- kube-system secrets (bootstrap tokens, system creds) ---
    status, body = _req("/api/v1/namespaces/kube-system/secrets")
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "KUBE_SYSTEM_SECRETS_UNAUTH",
            "detail": "Bootstrap tokens and system credentials exposed — kube-system secrets readable without auth",
            "host": host,
            "port": port,
        })

        # count items with non-empty data fields (base64 values) in the last response
        items = body.get("items", []) if isinstance(body, dict) else []
        readable = sum(1 for item in items if item.get("data"))
        if readable:
            findings.append({
                "severity": "HIGH",
                "title": "SECRET_DATA_READABLE",
                "detail": f"{readable} secrets with accessible base64-encoded data fields returned from kube-system",
                "host": host,
                "port": port,
            })

    # if we didn't already count from kube-system, try cluster-wide body
    if not any(f["title"] == "SECRET_DATA_READABLE" for f in findings):
        _, body2 = _req("/api/v1/secrets")
        if isinstance(body2, dict):
            items = body2.get("items", [])
            readable = sum(1 for item in items if item.get("data"))
            if readable:
                findings.append({
                    "severity": "HIGH",
                    "title": "SECRET_DATA_READABLE",
                    "detail": f"{readable} secrets with accessible base64-encoded data fields enumerated cluster-wide",
                    "host": host,
                    "port": port,
                })

    return findings


def check_k8s_storage_class_risks(host: str, port: int = 8001, timeout: float = 5.0) -> list:
    """Probe unauthenticated Kubernetes storage API endpoints for data-retention risks.

    Checks storage class exposure, Retain reclaim policies (PVs survive PVC
    deletion — data not wiped), and hostPath PersistentVolumes (host filesystem
    mounted into pods).

    Returns a list of finding dicts: {severity, title, detail, host, port}.
    """
    import urllib.request
    import ssl
    import json

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    findings = []
    base = f"https://{host}:{port}"

    def _req(path):
        url = base + path
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    raw = resp.read()
                    try:
                        return 200, json.loads(raw)
                    except Exception:
                        return 200, {}
                return resp.status, {}
        except urllib.error.HTTPError as e:
            return e.code, {}
        except Exception:
            return None, {}

    # --- storage class list ---
    status, body = _req("/apis/storage.k8s.io/v1/storageclasses")
    if status == 200:
        findings.append({
            "severity": "MEDIUM",
            "title": "STORAGE_CLASS_LIST_EXPOSED",
            "detail": "Storage infrastructure visible without auth via GET /apis/storage.k8s.io/v1/storageclasses",
            "host": host,
            "port": port,
        })

        # Retain reclaim policy — PVs persist after PVC deletion, data not wiped
        items = body.get("items", []) if isinstance(body, dict) else []
        retain_classes = [
            item.get("metadata", {}).get("name", "unknown")
            for item in items
            if item.get("reclaimPolicy") == "Retain"
        ]
        if retain_classes:
            findings.append({
                "severity": "HIGH",
                "title": "STORAGE_RETAIN_POLICY",
                "detail": (
                    f"StorageClasses with reclaimPolicy=Retain: {', '.join(retain_classes)}. "
                    "PersistentVolumes are NOT deleted when their PVCs are removed — "
                    "data remains on the backing store and is re-claimable by any future PVC."
                ),
                "host": host,
                "port": port,
            })

    # --- persistent volume list ---
    status, body = _req("/api/v1/persistentvolumes")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "PV_LIST_EXPOSED",
            "detail": "Persistent volume inventory (including host paths and NFS mounts) visible without auth via GET /api/v1/persistentvolumes",
            "host": host,
            "port": port,
        })

        # hostPath PVs — direct host filesystem mount into pods
        items = body.get("items", []) if isinstance(body, dict) else []
        hostpath_pvs = []
        for item in items:
            pv_name = item.get("metadata", {}).get("name", "unknown")
            spec = item.get("spec", {})
            if "hostPath" in spec:
                path = spec["hostPath"].get("path", "unknown")
                hostpath_pvs.append(f"{pv_name}:{path}")
        if hostpath_pvs:
            findings.append({
                "severity": "CRITICAL",
                "title": "HOSTPATH_PERSISTENT_VOLUME",
                "detail": (
                    f"PersistentVolumes mounting host filesystem paths: {'; '.join(hostpath_pvs)}. "
                    "A pod bound to any of these PVs can read/write host files directly — "
                    "trivial container escape if write access is granted."
                ),
                "host": host,
                "port": port,
            })

    return findings


if __name__ == '__main__':
    enum = DockerEnumerator()
    enum.enumerate_all()
    print(enum.report())
