"""
agent_loop.py — Single-shot LLM analysis of binary functions via the claude CLI.

Instead of a multi-turn ReAct loop via the Anthropic SDK (which requires
ANTHROPIC_API_KEY), all binary data is pre-fetched from ToolRegistry in Python,
assembled into a single prompt, and sent to `claude -p -` which uses the existing
claudeAiOauth credentials from ~/.claude/.credentials.json.

Public API is unchanged: AgentLoop, AnalysisResult, run(), run_patch(),
persist_result(), _model, _registry, _func_db, _build_result().

Architecture change: max_tool_calls is now unused (no loop). The tool_calls
field in AnalysisResult counts the number of pre-fetch calls made (0–4).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

from .tool_registry import ToolRegistry
from .context_builder import ContextBuilder
from .rag_retriever import RAGRetriever

_DEFAULT_MODEL = 'claude-opus-4-7'

# Appended to every prompt — overrides the ContextBuilder "call done()/tools"
# instructions since no tools are wired in the child session.
_JSON_INSTRUCTION = (
    '\n\n[OUTPUT INSTRUCTIONS]\n'
    'All binary data is pre-loaded above. No tool calls are available.\n'
    'Respond with ONLY a valid JSON object — no prose, no markdown fences:\n'
    '{"name": "snake_case_name", "role": "ROLE_FROM_TAXONOMY", '
    '"confidence": 0.0, "rationale": "explanation", "vuln_notes": ""}'
)

# Denied in every child session to block prompt-injection-to-shell paths.
# Untrusted firmware strings land in the prompt; Bash/Edit/Write must be off.
_DISALLOWED_TOOLS = 'Bash,Edit,Write,MultiEdit,WebSearch,WebFetch,Workflow,Agent,Task'


# ── Result type ────────────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    func_addr:    int
    name:         str
    role:         str
    confidence:   float
    rationale:    str
    vuln_notes:   str
    tool_calls:   int
    finished:     bool
    model:        str
    task:         str


# ── Agent loop ─────────────────────────────────────────────────────────────────

class AgentLoop:
    """
    Single-shot LLM analysis of a binary function via the claude CLI.

    Pre-fetches disassembly, strings, imports, and CFG from ToolRegistry,
    assembles them into one prompt, and calls `claude -p -` once.
    No ANTHROPIC_API_KEY required — uses the session's claudeAiOauth token.
    """

    def __init__(
        self,
        registry:       ToolRegistry,
        func_db=None,
        product:        str = 'unknown',
        version:        str = 'unknown',
        binary_hint:    str = '',
        binary_sha256:  str = '',
        max_tool_calls: int = 10,
        model:          str = _DEFAULT_MODEL,
        verbose:        bool = False,
    ):
        self._registry      = registry
        self._func_db       = func_db
        self._rag           = RAGRetriever(func_db) if func_db else None
        self._ctx           = ContextBuilder(product, version, binary_hint, max_tool_calls)
        self._binary_sha256 = binary_sha256
        self._model         = model
        self._verbose       = verbose

    # ── public API ────────────────────────────────────────────────────────────

    def run(
        self,
        func_addr:    int,
        task:         str = 'name_function',
        callees:      list[str] | None = None,
        callers:      list[str] | None = None,
        strings:      list[str] | None = None,
        size_hint:    str = 'unknown',
        cfg_summary:  str = '',
        role_hint:    str = '',
    ) -> AnalysisResult:
        """
        Analyze a single function. Pre-fetches all binary data, then makes one
        claude CLI call. Raises RuntimeError on transport/auth failure.
        """
        prior = self._retrieve_prior(func_addr, callees, role_hint)

        # Pre-fetch data that the tool loop would have requested lazily
        pre_calls = 0
        if strings is None:
            try:
                strings = json.loads(
                    self._registry._get_strings(func_addr)
                ).get('strings', [])
                pre_calls += 1
            except Exception:
                strings = []

        if not cfg_summary:
            try:
                cfg_summary = self._registry._get_cfg(func_addr)
                pre_calls += 1
            except Exception:
                cfg_summary = ''

        try:
            disasm = self._registry._get_disassembly(func_addr, n_insns=60)
            pre_calls += 1
        except Exception:
            disasm = '(disassembly unavailable)'

        try:
            imports = self._registry._get_imports(func_addr)
            pre_calls += 1
        except Exception:
            imports = '(imports unavailable)'

        system_prompt = self._ctx.system_prompt()
        user_message  = self._ctx.user_prompt(
            func_addr=func_addr,
            task=task,
            prior_findings=prior,
            size_hint=size_hint,
            callers=callers,
            callees=callees,
            strings=strings,
            cfg_summary=cfg_summary,
        )

        prompt = (
            f'{user_message}\n\n'
            f'[DISASSEMBLY]\n{disasm}\n\n'
            f'[IMPORTS]\n{imports}'
            f'{_JSON_INSTRUCTION}'
        )

        return self._run_cli(func_addr, task, system_prompt, prompt, pre_calls)

    def run_patch(
        self,
        func_addr_v1: int,
        func_addr_v2: int,
        disasm_v1:    str,
        disasm_v2:    str,
        version_v1:   str,
        version_v2:   str,
    ) -> AnalysisResult:
        """Compare two function versions. Raises RuntimeError on transport failure."""
        prior = self._retrieve_prior(func_addr_v1, callees=None, role_hint='')
        patch_prompt = (
            self._ctx.patch_prompt(
                func_addr_v1, func_addr_v2,
                disasm_v1, disasm_v2,
                version_v1, version_v2,
                prior_findings=prior,
            )
            + _JSON_INSTRUCTION
        )
        return self._run_cli(
            func_addr_v1, 'patch_analysis',
            self._ctx.system_prompt(), patch_prompt,
            pre_calls=0,
        )

    # ── result persistence ────────────────────────────────────────────────────

    def persist_result(self, result: AnalysisResult, binary_sha256: str):
        """Write a high-confidence result back into func_id_db as ANGR_INFERRED."""
        if self._func_db is None:
            return
        if result.confidence < 0.5 or not result.name:
            return

        import sys, pathlib
        sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
        from func_id_db import FuncRecord

        try:
            self._func_db.add_func(FuncRecord(
                binary_sha256=binary_sha256,
                va=result.func_addr,
                name=result.name,
                role=result.role,
                confidence='ANGR_INFERRED',
                notes=(
                    f'LLM-inferred ({result.model}, {result.tool_calls} pre-fetched sources). '
                    f'{result.rationale[:200]}'
                ),
            ))
        except Exception:
            pass

    # ── CLI orchestration ─────────────────────────────────────────────────────

    def _run_cli(
        self,
        func_addr:  int,
        task:       str,
        system:     str,
        prompt:     str,
        pre_calls:  int,
    ) -> AnalysisResult:
        # Transport errors propagate — a broken backend must not silently fill
        # func_id_db with zero-confidence rows.
        text = self._call_claude_cli(system, prompt)

        try:
            done_args = self._parse_json_response(text)
            finished = True
        except ValueError:
            # Model responded but not in JSON — soft failure, not a backend error
            if self._verbose:
                print(f'[llm_analyst] JSON parse failed, raw: {text[:200]}')
            done_args = {
                'name':       'unknown__parse_failed',
                'role':       'UNKNOWN',
                'confidence': 0.0,
                'rationale':  text[:500],
                'vuln_notes': '',
            }
            finished = False

        return self._build_result(func_addr, task, done_args, pre_calls, finished)

    def _call_claude_cli(self, system: str, prompt: str) -> str:
        """
        Invoke `claude -p -` in an isolated child session and return the text result.

        Isolation:
          --bare              skips Stop/PostToolUse hooks and auto-memory so
                              batch calls don't trigger chimes or persist state
          --system-prompt     replaces the default system prompt (incl. CLAUDE.md)
                              with the RE-specific prompt
          --disallowedTools   removes Bash/Edit/Write to block prompt-injection paths
          cwd=tempdir         no project CLAUDE.md in scope

        Raises RuntimeError on non-zero exit or is_error=true in the envelope.
        """
        cmd = [
            'claude', '-p', '-',
            '--output-format', 'json',
            '--system-prompt', system,
            '--disallowedTools', _DISALLOWED_TOOLS,
        ]
        if self._model:
            cmd += ['--model', self._model]

        if self._verbose:
            print(f'[llm_analyst] calling claude CLI '
                  f'(model={self._model}, prompt_len={len(prompt)})')

        # Run in a tempdir so no project CLAUDE.md loads
        with tempfile.TemporaryDirectory() as cwd:
            proc = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=cwd,
            )

        if proc.returncode != 0:
            raise RuntimeError(
                f'claude CLI exit {proc.returncode}: '
                f'{(proc.stderr or proc.stdout)[:300]}'
            )

        # --output-format json produces a JSON array of events; find the result event
        try:
            events = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return proc.stdout.strip()

        result_event = next(
            (e for e in events if e.get('type') == 'result'),
            None,
        )
        if result_event is None:
            raise RuntimeError(f'no result event in claude CLI output: {proc.stdout[:300]}')

        if result_event.get('is_error'):
            raise RuntimeError(
                f'claude CLI is_error=true: {result_event.get("result", "")[:300]}'
            )

        return result_event.get('result', '').strip()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _parse_json_response(self, text: str) -> dict:
        """
        Extract a JSON object from the model's text response.
        Strips markdown code fences if present. Raises ValueError if not found.
        """
        cleaned = re.sub(r'^```(?:json)?\s*\n?', '', text, flags=re.MULTILINE)
        cleaned = re.sub(r'\n?```\s*$', '', cleaned, flags=re.MULTILINE)
        match = re.search(r'\{.*\}', cleaned.strip(), re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        raise ValueError(f'no valid JSON object in response: {text[:200]}')

    def _retrieve_prior(
        self, func_addr: int, callees: list | None, role_hint: str
    ) -> list[dict]:
        if self._rag is None:
            return []
        return self._rag.retrieve(
            func_addr=func_addr,
            binary_sha256=self._binary_sha256,
            callees=callees or [],
            role_hint=role_hint,
        )

    def _build_result(
        self,
        func_addr:  int,
        task:       str,
        done_args:  dict,
        tool_calls: int,
        finished:   bool,
    ) -> AnalysisResult:
        try:
            confidence = float(done_args.get('confidence', 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        return AnalysisResult(
            func_addr=func_addr,
            name=done_args.get('name', ''),
            role=done_args.get('role', 'UNKNOWN'),
            confidence=confidence,
            rationale=done_args.get('rationale', ''),
            vuln_notes=done_args.get('vuln_notes', ''),
            tool_calls=tool_calls,
            finished=finished,
            model=self._model,
            task=task,
        )
