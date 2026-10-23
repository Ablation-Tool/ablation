"""
lethal_trifecta_scanner.py: Lethal trifecta detector.

Flags binaries that combine three co-present risk signals:

  1. Private/sensitive data strings: api_key, private_key, secret, credential,
     password, token, certificate, jwt, bearer
  2. Untrusted input sources: recv, recvfrom, read, fgets, getenv, scanf
     in the PLT import table
  3. Outbound communication sinks: connect, send, SSL_connect, curl_easy_perform
     or LLM API host strings in rodata

When all three are present in the same binary, the program can receive
attacker-controlled input, has access to sensitive data, and can exfiltrate
it outbound. This is the minimal condition for a data-exfiltration or
prompt-injection-to-exfiltration attack path.

Severity is HIGH when all three are present. The module also reports MEDIUM
when exactly two of the three are present, to flag near-trifecta conditions.

Usage:
    scanner = LethalTrifectaScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


# Private/sensitive data indicator strings (byte patterns in rodata)
_PRIVATE_DATA_STRINGS: list[bytes] = [
    b'api_key', b'apikey', b'api_secret',
    b'private_key', b'privatekey',
    b'secret', b'credential', b'credentials',
    b'password', b'passwd',
    b'access_token', b'auth_token', b'bearer',
    b'jwt', b'certificate', b'cert_chain',
    b'private_cert', b'client_secret',
    b'aws_secret', b'aws_access_key',
]

# Untrusted input source PLT imports
_INPUT_SOURCE_IMPORTS: frozenset = frozenset({
    'recv', 'recvfrom', 'recvmsg',
    'read', 'fread', 'fgets', 'gets',
    'getenv', 'scanf', 'sscanf', 'fscanf',
    'HttpQueryInfo', 'WinHttpQueryHeaders',
})

# Outbound communication sink PLT imports and host strings
_OUTBOUND_PLT: frozenset = frozenset({
    'connect', 'send', 'sendto', 'sendmsg',
    'SSL_connect', 'SSL_write',
    'curl_easy_perform', 'curl_easy_setopt',
    'BIO_write', 'SSL_CTX_new',
    'InternetConnect', 'HttpSendRequest',
    'WinHttpConnect', 'WSAConnect',
    'getaddrinfo', 'gethostbyname',
})

# LLM API host strings (also count as outbound)
_LLM_HOST_STRINGS: list[bytes] = [
    b'api.openai.com', b'api.anthropic.com',
    b'generativelanguage.googleapis.com',
    b'api.cohere.ai', b'api.mistral.ai',
    b'bedrock-runtime.',
]


@dataclass
class TrifectaFinding:
    has_private_data:  bool
    has_input_source:  bool
    has_outbound:      bool
    private_matches:   list[str]   # matched sensitive strings
    input_imports:     list[str]   # matched input PLT imports
    outbound_signals:  list[str]   # matched outbound imports or host strings
    severity:          str         # HIGH / MEDIUM

    def _score(self) -> int:
        return int(self.has_private_data) + int(self.has_input_source) + int(self.has_outbound)

    def fmt(self) -> str:
        lines = [f"  {self.severity:6s}  [LETHAL_TRIFECTA]  {self._score()}/3 signals present"]
        if self.has_private_data:
            s = ', '.join(self.private_matches[:4])
            lines.append(f"         private_data: {s}")
        if self.has_input_source:
            lines.append(f"         input_sources: {', '.join(self.input_imports)}")
        if self.has_outbound:
            lines.append(f"         outbound: {', '.join(self.outbound_signals[:4])}")
        return '\n'.join(lines)


class LethalTrifectaScanner:
    """Detect the lethal trifecta: private data + untrusted input + outbound comms."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'LethalTrifectaScanner':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        obj._ctx  = ctx
        return obj

    def _load_ctx(self):
        if self._ctx is not None:
            return self._ctx
        from ablation.analyzers.binary_context import BinaryContext
        self._ctx = BinaryContext.load_or_build(self._path)
        return self._ctx

    def _read_raw(self) -> bytes:
        try:
            return open(self._path, 'rb').read()
        except OSError:
            return b''

    def scan(self) -> List[TrifectaFinding]:
        raw = self._read_raw()
        if not raw:
            return []

        ctx = self._load_ctx()
        plt_names = frozenset(n.split('@')[0].lstrip('_') for _, n in ctx.plt.items())

        # Signal 1: private data strings
        private_matches = [s.decode('ascii') for s in _PRIVATE_DATA_STRINGS if s in raw]
        has_private = bool(private_matches)

        # Signal 2: input source imports
        input_imports = sorted(plt_names & _INPUT_SOURCE_IMPORTS)
        has_input = bool(input_imports)

        # Signal 3: outbound communication
        outbound_imports = sorted(plt_names & _OUTBOUND_PLT)
        llm_hosts = [h.decode('ascii') for h in _LLM_HOST_STRINGS if h in raw]
        outbound_signals = outbound_imports + llm_hosts
        has_outbound = bool(outbound_signals)

        score = int(has_private) + int(has_input) + int(has_outbound)
        if score < 2:
            return []

        severity = 'HIGH' if score == 3 else 'MEDIUM'
        return [TrifectaFinding(
            has_private_data=has_private,
            has_input_source=has_input,
            has_outbound=has_outbound,
            private_matches=private_matches,
            input_imports=input_imports,
            outbound_signals=outbound_signals,
            severity=severity,
        )]

    def report(self, findings: Optional[List[TrifectaFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'LethalTrifectaScanner: no trifecta pattern in {self._path}'
        lines = [f'LethalTrifectaScanner: trifecta finding in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
