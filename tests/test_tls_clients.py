import json
import ssl
from unittest.mock import patch

import modules.k8s_enum as k8s
import modules.llm_enum as llm
import modules.nexus_dashboard_enum as nexus
import modules.nxos_enum as nxos


class Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, _size=-1):
        return self.payload


def assert_secure_context(ctx):
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_nexus_login_uses_verified_tls():
    captured = {}

    def fake_urlopen(req, context, timeout):
        captured['context'] = context
        return Response(b'{"token":"test-token"}')

    with patch('urllib.request.urlopen', fake_urlopen):
        assert nexus._nd_login('controller', 'user', 'password') == 'test-token'

    assert_secure_context(captured['context'])


def test_nxos_authenticated_context_verifies_tls():
    assert_secure_context(nxos._SSL_CTX)


def test_kubernetes_token_request_verifies_tls_without_ca_fallback():
    enumerator = k8s.K8sEnumerator()
    enumerator.token = 'service-account-token'
    captured = {}

    def fake_urlopen(req, context, timeout):
        captured['context'] = context
        captured['authorization'] = req.get_header('Authorization')
        return Response(b'{"items":[]}')

    with patch('urllib.request.urlopen', fake_urlopen):
        assert enumerator._api_get('/api/v1/namespaces') == {'items': []}

    assert captured['authorization'] == 'Bearer service-account-token'
    assert_secure_context(captured['context'])


def test_kubernetes_ca_context_keeps_hostname_verification():
    enumerator = k8s.K8sEnumerator()
    enumerator.ca_cert = b'test-ca'
    with patch('ssl.SSLContext.load_verify_locations', return_value=None):
        context = enumerator._api_ssl_context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_llm_get_does_not_retry_with_insecure_tls():
    calls = []

    def fail_urlopen(req, timeout, context):
        calls.append(context)
        raise ssl.SSLError('certificate verify failed')

    with patch('urllib.request.urlopen', fail_urlopen):
        assert llm._http_get('https://model.local/v1/models') == (-1, '', {})

    assert len(calls) == 1
    assert_secure_context(calls[0])


def test_llm_post_does_not_retry_with_insecure_tls():
    calls = []

    def fail_urlopen(req, timeout, context):
        calls.append(context)
        raise ssl.SSLError('certificate verify failed')

    with patch('urllib.request.urlopen', fail_urlopen):
        assert llm._http_post('https://model.local/v1/completions', {}) == (-1, '', {})

    assert len(calls) == 1
    assert_secure_context(calls[0])
