"""
agent_loop.py — Single-shot LLM analysis of binary functions.

Sends pre-fetched binary data (disassembly, strings, imports, CFG) in one
prompt; returns a structured AnalysisResult.  Two transport backends:

  SDK (preferred): uses anthropic.Anthropic().messages.create() — requires
    ANTHROPIC_API_KEY env var or explicit api_key= argument.  Returns real
    token counts for the execution log.

  CLI (fallback): shells out to `claude -p -` via subprocess.  Used when no
    API key is available (e.g., oauth-only sessions).  Token counts are 0.

Cascade routing (book Ch. 8 pattern): model is auto-selected per task unless
overridden with model=.  Cheap tasks (naming, struct) use a fast model;
complex tasks (exploit chain) use the full model.

Public API is unchanged: AgentLoop, AnalysisResult, run(), run_patch(),
persist_result(), _model, _registry, _func_db, _build_result().
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Optional

from .tool_registry import ToolRegistry
from .context_builder import ContextBuilder
from .rag_retriever import RAGRetriever
from .schemas import AnalysisOutput, parse_analysis_output

# ── cascade routing ────────────────────────────────────────────────────────────
# Maps task name → model tier.  Only ~20% of tasks (exploit_chain) justify the
# full frontier model.  Callers can override per-instance with model=.

_MODEL_FOR_TASK: dict[str, str] = {
    'name_function':     'claude-haiku-4-5',
    'struct_reconstruct': 'claude-haiku-4-5',
    'vuln_hypothesis':   'claude-sonnet-4-6',
    'patch_analysis':    'claude-sonnet-4-6',
    'exploit_chain':     'claude-opus-4-7',
}
_DEFAULT_TASK_MODEL = 'claude-sonnet-4-6'

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
    Single-shot LLM analysis of a binary function.

    Pre-fetches disassembly, strings, imports, and CFG from ToolRegistry,
    assembles them into one prompt, and calls the Anthropic SDK (or falls back
    to the claude CLI subprocess when no API key is available).
    """

    def __init__(
        self,
        registry:        ToolRegistry,
        func_db=None,
        product:         str = 'unknown',
        version:         str = 'unknown',
        binary_hint:     str = '',
        binary_sha256:   str = '',
        max_tool_calls:  int = 10,
        model:           Optional[str] = None,
        api_key:         Optional[str] = None,
        knowledge_graph=None,
        arch:            str = '',
        fmt:             str = '',
        verbose:         bool = False,
    ):
        self._registry      = registry
        self._func_db       = func_db
        self._rag           = RAGRetriever(func_db) if func_db else None
        self._ctx           = ContextBuilder(product, version, binary_hint, max_tool_calls)
        self._binary_sha256 = binary_sha256
        self._model         = model      # None = use cascade routing per task
        self._api_key       = api_key
        self._kg            = knowledge_graph
        self._arch          = arch
        self._fmt           = fmt
        self._verbose       = verbose
        self._kg_context    = self._fetch_kg_context()

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
        LLM call via SDK or claude CLI. Raises RuntimeError on transport failure.
        """
        prior = self._retrieve_prior(func_addr, callees, role_hint)

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

        system_prompt = self._ctx.system_prompt(kg_context=self._kg_context)
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

        return self._run_analysis(func_addr, task, system_prompt, prompt, pre_calls)

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
        return self._run_analysis(
            func_addr_v1, 'patch_analysis',
            self._ctx.system_prompt(kg_context=self._kg_context), patch_prompt,
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

    # ── KnowledgeGraph memory interface ───────────────────────────────────────

    def _fetch_kg_context(self) -> str:
        """
        Fetch arch/format context from the KnowledgeGraph at construction time.

        Returns an empty string when no KG is configured, when arch is unknown,
        or when the KG raises.  Fetched once at construction so every run() call
        shares the same context without paying the SQLite round-trip again.
        """
        if self._kg is None or not self._arch:
            return ''
        try:
            return self._kg.get_context_for_binary(
                arch=self._arch,
                fmt=self._fmt or '',
                intent='sweep',
            )
        except Exception as exc:
            if self._verbose:
                print(f'[llm_analyst] KG context fetch failed: {exc}')
            return ''

    # ── transport ─────────────────────────────────────────────────────────────

    def _use_sdk(self) -> bool:
        """True when an API key is available (explicit arg or ANTHROPIC_API_KEY env)."""
        return bool(self._api_key or os.environ.get('ANTHROPIC_API_KEY'))

    def _effective_model(self, task: str) -> str:
        """Return the model to use for this task — explicit override or cascade default."""
        if self._model:
            return self._model
        return _MODEL_FOR_TASK.get(task, _DEFAULT_TASK_MODEL)

    def _run_analysis(
        self,
        func_addr:  int,
        task:       str,
        system:     str,
        prompt:     str,
        pre_calls:  int,
    ) -> AnalysisResult:
        """
        Dispatch to SDK or CLI, parse with Pydantic, log execution, return result.
        Transport errors propagate — a broken backend must not silently fill
        func_id_db with zero-confidence rows.
        """
        model = self._effective_model(task)
        t0 = time.monotonic()

        if self._use_sdk():
            text, in_tok, out_tok = self._call_sdk(system, prompt, model)
        else:
            text  = self._call_claude_cli(system, prompt, model)
            in_tok = out_tok = 0

        latency_ms = int((time.monotonic() - t0) * 1000)

        try:
            output   = parse_analysis_output(text)
            finished = True
        except Exception:
            if self._verbose:
                print(f'[llm_analyst] parse failed; raw: {text[:200]}')
            output = AnalysisOutput(
                name='unknown__parse_failed',
                role='UNKNOWN',
                confidence=0.0,
                rationale=text[:500],
                vuln_notes='',
            )
            finished = False

        result = self._build_result(func_addr, task, output, pre_calls, finished, model)

        if self._func_db and hasattr(self._func_db, 'log_execution'):
            self._func_db.log_execution(
                task=task,
                func_addr=func_addr,
                binary_sha256=self._binary_sha256,
                model=model,
                input_tokens=in_tok,
                output_tokens=out_tok,
                latency_ms=latency_ms,
                finished=finished,
                result_name=result.name,
                result_role=result.role,
                result_confidence=result.confidence,
            )

        return result

    def _call_sdk(self, system: str, prompt: str, model: str) -> tuple[str, int, int]:
        """
        Call the Anthropic SDK directly. Returns (text, input_tokens, output_tokens).
        Raises RuntimeError on API error or empty content.
        """
        import anthropic

        api_key = self._api_key or os.environ.get('ANTHROPIC_API_KEY')
        client  = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

        if self._verbose:
            print(f'[llm_analyst] sdk call (model={model}, prompt_len={len(prompt)})')

        message = client.messages.create(
            model=model,
            max_tokens=512,
            system=system,
            messages=[{'role': 'user', 'content': prompt}],
        )

        if not message.content:
            raise RuntimeError('Anthropic SDK returned empty content')

        text = message.content[0].text
        return text, message.usage.input_tokens, message.usage.output_tokens

    def _call_claude_cli(self, system: str, prompt: str, model: str) -> str:
        """
        Invoke `claude -p -` in an isolated child session and return the text result.

        Isolation:
          --system-prompt     replaces the default system prompt (incl. CLAUDE.md)
          --disallowedTools   removes Bash/Edit/Write to block prompt-injection paths
          cwd=tempdir         no project CLAUDE.md loads in the child session

        Raises RuntimeError on non-zero exit or is_error=true in the envelope.
        """
        cmd = [
            'claude', '-p', '-',
            '--output-format', 'json',
            '--system-prompt', system,
            '--disallowedTools', _DISALLOWED_TOOLS,
            '--model', model,
        ]

        if self._verbose:
            print(f'[llm_analyst] cli call (model={model}, prompt_len={len(prompt)})')

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
        output:     AnalysisOutput,
        tool_calls: int,
        finished:   bool,
        model:      str,
    ) -> AnalysisResult:
        return AnalysisResult(
            func_addr=func_addr,
            name=output.name,
            role=output.role,
            confidence=output.confidence,
            rationale=output.rationale,
            vuln_notes=output.vuln_notes,
            tool_calls=tool_calls,
            finished=finished,
            model=model,
            task=task,
        )
