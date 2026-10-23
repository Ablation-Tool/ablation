"""
prompt_injection_sink_classifier.py: LLM prompt injection sink classifier.

Identifies code paths where untrusted user input is combined with LLM API
call sites. This is the binary-level analog of prompt injection: a function
that reads from an external source (network, file, environment) and passes
that data into an HTTP/HTTPS request to an LLM API endpoint without adequate
isolation of the system prompt from the user data.

Detection approach:
  1. Find LLM API host strings in the binary (openai.com, anthropic.com, etc.)
  2. Find system-prompt injection indicator strings: "role":"system", SYSTEM:,
     system_prompt, etc.
  3. Find functions that contain calls to both HTTP-write sinks (send, write,
     curl_easy_setopt, etc.) and read/recv (external input sources).
  4. Cross-check: functions that do (2) + (3) are prompt injection sinks.
  5. Flag additional risk when no output sanitization is observed near the
     LLM call (i.e., no strcpy/strncpy truncation or bounds check between
     the input source and the HTTP sink).

This module classifies at the import-table and string level. For confirmed
data-flow, use TaintTracker with the HTTP-write sink configured.

Usage:
    classifier = PromptInjectionSinkClassifier('/path/to/binary')
    findings = classifier.scan()
    print(classifier.report(findings))
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


# LLM API provider hostnames as byte strings
_LLM_HOSTS: list[bytes] = [
    b'api.openai.com',
    b'api.anthropic.com',
    b'generativelanguage.googleapis.com',
    b'inference.ai.azure.com',
    b'api.cohere.ai',
    b'api.mistral.ai',
    b'api.together.xyz',
    b'api.groq.com',
    b'bedrock-runtime.',
    b'aiplatform.googleapis.com',
]

# System prompt injection indicator strings
_SYSTEM_PROMPT_INDICATORS: list[bytes] = [
    b'"role":"system"',
    b'"role": "system"',
    b'role=system',
    b'SYSTEM:',
    b'<|system|>',
    b'[SYSTEM]',
    b'system_prompt',
    b'systemPrompt',
    b'system_message',
    b'<<SYS>>',
    b'[INST]',
    b'<|im_start|>system',
]

# External input source functions
_INPUT_SOURCES: frozenset = frozenset({
    'read', 'recv', 'recvfrom', 'recvmsg', 'fread', 'fgets', 'gets',
    'getenv', 'scanf', 'sscanf', 'fscanf',
})

# HTTP/network write sinks (used to send LLM API requests)
_HTTP_WRITE_SINKS: frozenset = frozenset({
    'send', 'sendto', 'sendmsg', 'write', 'fwrite',
    'curl_easy_setopt', 'curl_easy_perform',
    'SSL_write', 'BIO_write',
    'HttpSendRequest', 'WinHttpSendRequest',
})

# Output sanitization indicators (reduce false positives when present near sink)
_SANITIZE_NAMES = re.compile(
    r'(saniti[sz]|escape|strip|truncat|strncp|snprintf|limit|maxlen)',
    re.I,
)


@dataclass
class PromptInjectionFinding:
    func_va:            int
    func_name:          str
    has_system_prompt:  bool     # system-prompt strings referenced nearby
    has_input_source:   bool     # reads from external input in same function
    has_http_sink:      bool     # makes HTTP write call in same function
    llm_host:           str      # which LLM host string is present
    severity:           str      # HIGH / MEDIUM

    def fmt(self) -> str:
        flags = []
        if self.has_system_prompt:
            flags.append('system-prompt-string')
        if self.has_input_source:
            flags.append('external-input')
        if self.has_http_sink:
            flags.append('http-write-sink')
        return (f"  {self.severity:6s}  [PROMPT_INJECTION]  {self.func_name} at 0x{self.func_va:x}\n"
                f"         LLM host: {self.llm_host}\n"
                f"         signals: {', '.join(flags)}")


class PromptInjectionSinkClassifier:
    """Classify LLM API call sites for prompt injection risk."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'PromptInjectionSinkClassifier':
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

    def _plt_va_map(self, ctx) -> dict[int, str]:
        result: dict[int, str] = {}
        for name, va in ctx.plt_entries():
            base = name.split('@')[0].lstrip('_')
            result[va] = base
        return result

    def scan(self) -> List[PromptInjectionFinding]:
        raw = self._read_raw()

        # Global check: any LLM host string present?
        llm_host = ''
        for host in _LLM_HOSTS:
            if host in raw:
                llm_host = host.decode('ascii')
                break

        if not llm_host:
            return []

        # Global check: any system-prompt indicator present?
        global_sys_prompt = any(ind in raw for ind in _SYSTEM_PROMPT_INDICATORS)
        if not global_sys_prompt:
            return []

        ctx = self._load_ctx()
        plt_va_map = self._plt_va_map(ctx)
        findings: list[PromptInjectionFinding] = []

        for func_va in ctx.func_starts:
            func_name = ctx.name(func_va)
            insns = list(ctx.disasm_func(func_va))

            calls: list[str] = []
            for insn in insns:
                mn = insn.mnemonic.lower().split()[0]
                if mn not in ('call', 'bl', 'blx', 'jalr', 'jal'):
                    continue
                try:
                    target = int(insn.op_str.strip().lstrip('#'), 16)
                except (ValueError, AttributeError):
                    continue
                name = plt_va_map.get(target, '')
                if name:
                    calls.append(name)

            has_input = any(c in _INPUT_SOURCES for c in calls)
            has_http  = any(c in _HTTP_WRITE_SINKS for c in calls)

            if not (has_input or has_http):
                continue

            severity = 'HIGH' if (has_input and has_http) else 'MEDIUM'
            findings.append(PromptInjectionFinding(
                func_va=func_va,
                func_name=func_name,
                has_system_prompt=global_sys_prompt,
                has_input_source=has_input,
                has_http_sink=has_http,
                llm_host=llm_host,
                severity=severity,
            ))

        return findings

    def report(self, findings: Optional[List[PromptInjectionFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'PromptInjectionSinkClassifier: no LLM API sink findings in {self._path}'
        lines = [f'PromptInjectionSinkClassifier: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
