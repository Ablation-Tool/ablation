"""
policy_engine_absence_detector.py: AI/LLM policy engine absence detector.

Detects binaries that call AI/LLM inference endpoints but lack observable
policy enforcement imports: rate limiting, input validation, authorization
checks, or audit logging.

A binary with LLM API calls and no policy layer is the AI-agent analogue of
"command execution without authentication": the agent will forward any input
to the model and act on the model response without guardrails.

Detection strategy:
  1. Scan PLT imports and rodata strings for AI API indicators:
       - HTTP library usage with AI provider hostnames (api.openai.com,
         api.anthropic.com, huggingface.co, bedrock.amazonaws.com, etc.)
       - Direct function/symbol names from AI SDKs
  2. Scan PLT imports for policy-function indicators:
       - Rate limiting: token_bucket, rate_limit, throttle, quota
       - Input validation: validate_input, sanitize, schema_check
       - Authorization: check_permission, authorize, rbac, acl
       - Audit logging: audit_log, write_audit, log_event
  3. If AI indicators present and policy indicators absent: HIGH finding.
  4. If AI indicators present and some policy present: MEDIUM finding noting
     which policy layers are missing.

Usage:
    detector = PolicyEngineAbsenceDetector('/path/to/binary')
    findings = detector.scan()
    print(detector.report(findings))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    detector = PolicyEngineAbsenceDetector.from_context(ctx)
    findings = detector.scan()
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


# ── AI/LLM indicator patterns ──────────────────────────────────────────────────

_AI_HOSTNAMES = frozenset({
    b'api.openai.com',
    b'api.anthropic.com',
    b'huggingface.co',
    b'bedrock.amazonaws.com',
    b'generativelanguage.googleapis.com',
    b'api.cohere.ai',
    b'api.together.xyz',
    b'api.mistral.ai',
    b'api.groq.com',
    b'inference.baseten.co',
    b'openrouter.ai',
})

_AI_SDK_PATTERNS = [
    re.compile(rb'openai'),
    re.compile(rb'anthropic'),
    re.compile(rb'langchain'),
    re.compile(rb'llamaindex'),
    re.compile(rb'transformers\.pipeline'),
    re.compile(rb'ChatCompletion'),
    re.compile(rb'completions\.create'),
    re.compile(rb'messages\.create'),
    re.compile(rb'GenerateContent'),
    re.compile(rb'invoke_model'),           # AWS Bedrock
    re.compile(rb'chat\.completions'),
]

_AI_PLT_NAMES = frozenset({
    'openai_create', 'anthropic_messages', 'llm_chat', 'llm_complete',
    'ai_inference', 'model_invoke',
})


# ── Policy indicator patterns ──────────────────────────────────────────────────

_POLICY_GROUPS: dict[str, list[re.Pattern]] = {
    'rate_limiting': [
        re.compile(rb'rate.?limit', re.I),
        re.compile(rb'token.?bucket', re.I),
        re.compile(rb'throttl', re.I),
        re.compile(rb'quota', re.I),
        re.compile(rb'max_requests', re.I),
        re.compile(rb'requests_per_', re.I),
    ],
    'input_validation': [
        re.compile(rb'validate.?input', re.I),
        re.compile(rb'sanitize', re.I),
        re.compile(rb'schema.?check', re.I),
        re.compile(rb'input.?filter', re.I),
        re.compile(rb'prompt.?filter', re.I),
        re.compile(rb'content.?policy', re.I),
    ],
    'authorization': [
        re.compile(rb'check.?perm', re.I),
        re.compile(rb'authorize', re.I),
        re.compile(rb'\brbac\b', re.I),
        re.compile(rb'\bacl\b', re.I),
        re.compile(rb'is_allowed', re.I),
        re.compile(rb'has_access', re.I),
    ],
    'audit_logging': [
        re.compile(rb'audit.?log', re.I),
        re.compile(rb'write.?audit', re.I),
        re.compile(rb'log.?event', re.I),
        re.compile(rb'access.?log', re.I),
        re.compile(rb'request.?log', re.I),
    ],
}


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class PolicyAbsenceFinding:
    ai_indicators:       list[str]    # what AI usage was detected
    missing_layers:      list[str]    # which policy layers are absent
    present_layers:      list[str]    # which policy layers are present
    severity:            str          # HIGH / MEDIUM

    def fmt(self) -> str:
        ai_str = '; '.join(self.ai_indicators[:3])
        missing = ', '.join(self.missing_layers)
        present = ', '.join(self.present_layers) if self.present_layers else 'none'
        return (f"  {self.severity:6s}  [POLICY_ENGINE_ABSENT]\n"
                f"         AI indicators: {ai_str}\n"
                f"         missing policy layers: {missing}\n"
                f"         present policy layers: {present}")


# ── Detector ───────────────────────────────────────────────────────────────────

class PolicyEngineAbsenceDetector:
    """Detect AI/LLM calls without policy enforcement in firmware binaries."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'PolicyEngineAbsenceDetector':
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

    def _detect_ai_indicators(self, raw: bytes, plt_names: frozenset) -> list[str]:
        indicators: list[str] = []
        for hostname in _AI_HOSTNAMES:
            if hostname in raw:
                indicators.append(f'hostname:{hostname.decode()}')
        for pat in _AI_SDK_PATTERNS:
            m = pat.search(raw)
            if m:
                matched = m.group().decode('ascii', errors='replace')
                indicators.append(f'string:{matched}')
        for name in plt_names:
            if name in _AI_PLT_NAMES:
                indicators.append(f'plt:{name}')
        return list(dict.fromkeys(indicators))  # deduplicate, preserve order

    def _detect_policy_layers(self, raw: bytes) -> tuple[list[str], list[str]]:
        present: list[str] = []
        missing: list[str] = []
        for layer_name, patterns in _POLICY_GROUPS.items():
            found = any(p.search(raw) for p in patterns)
            if found:
                present.append(layer_name)
            else:
                missing.append(layer_name)
        return present, missing

    def scan(self) -> List[PolicyAbsenceFinding]:
        raw = self._read_raw()
        if not raw:
            return []

        # Get PLT names for symbol-based detection
        plt_names: frozenset = frozenset()
        try:
            ctx = self._load_ctx()
            plt_names = frozenset(
                n.split('@')[0].lstrip('_')
                for n, _ in ctx.plt_entries()
            )
        except Exception:
            pass

        ai_indicators = self._detect_ai_indicators(raw, plt_names)
        if not ai_indicators:
            return []

        present_layers, missing_layers = self._detect_policy_layers(raw)
        if not missing_layers:
            return []  # all four policy layers present

        severity = 'HIGH' if not present_layers else 'MEDIUM'
        return [PolicyAbsenceFinding(
            ai_indicators=ai_indicators,
            missing_layers=missing_layers,
            present_layers=present_layers,
            severity=severity,
        )]

    def report(self, findings: Optional[List[PolicyAbsenceFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'PolicyEngineAbsenceDetector: no AI-without-policy pattern in {self._path}'
        lines = [f'PolicyEngineAbsenceDetector: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
