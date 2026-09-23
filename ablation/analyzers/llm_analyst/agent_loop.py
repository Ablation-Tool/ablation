"""
agent_loop.py — ReAct agent loop for LLM-assisted binary analysis.

Loop structure:
  system prompt → initial user message (context)
  → Claude responds with tool_use blocks
  → dispatch each tool via tool_registry
  → inject tool_result back as user message
  → repeat until Claude calls done() or budget exhausted

Budget governor: hard stop at max_tool_calls.
Loop detector: identical tool+args pair terminates with a warning injection.
"""

from __future__ import annotations

import json
import os
import hashlib
from dataclasses import dataclass, field
from typing import Optional

import anthropic

from .tool_registry import TOOL_SCHEMAS, ToolRegistry
from .context_builder import ContextBuilder
from .rag_retriever import RAGRetriever

# Default model — capable enough for RE reasoning without Opus cost
_DEFAULT_MODEL = 'claude-sonnet-5'


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
    finished:     bool   # True = done() called; False = budget exhausted
    model:        str
    task:         str


# ── Agent loop ─────────────────────────────────────────────────────────────────

class AgentLoop:
    """
    Drives Claude through a ReAct tool-calling loop to analyze a binary function.

    Usage:
        registry = ToolRegistry(binary_path, func_db)
        loop = AgentLoop(registry, func_db=func_db, product='lina', version='9.16.4.18')
        result = loop.run(func_addr=0x212a669, task='name_function')
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
        self._max_calls     = max_tool_calls
        self._model         = model
        self._verbose       = verbose
        self._client        = anthropic.Anthropic()

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
        Run the ReAct loop for a single function.
        Returns AnalysisResult whether or not done() was called.
        """
        prior = self._retrieve_prior(func_addr, callees, role_hint)

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

        messages = [{'role': 'user', 'content': user_message}]
        tool_call_count = 0
        seen_calls: set[str] = set()   # for loop detection

        while tool_call_count < self._max_calls:
            response = self._call_claude(system_prompt, messages)
            assistant_content = response.content

            # Append the full assistant turn
            messages.append({'role': 'assistant', 'content': assistant_content})

            # Collect all tool_use blocks in this turn
            tool_uses = [b for b in assistant_content if b.type == 'tool_use']

            if not tool_uses:
                # Text-only response — model chose to stop without calling done()
                break

            # Process each tool call; collect results for the user turn
            tool_results = []
            done_result  = None

            for tool_use in tool_uses:
                tool_call_count += 1

                # Loop detection
                call_sig = self._call_signature(tool_use.name, tool_use.input)
                if call_sig in seen_calls:
                    result_content = json.dumps({
                        'error': 'LOOP_DETECTED — you already called this tool with these args. '
                                 'Use done() to finish or try a different tool.'
                    })
                    if self._verbose:
                        print(f'[loop] {tool_use.name}({tool_use.input})')
                else:
                    seen_calls.add(call_sig)

                    if tool_use.name == 'done':
                        done_result = tool_use.input
                        result_content = json.dumps({'status': 'analysis complete'})
                    else:
                        result_content = self._registry.dispatch(tool_use.name, tool_use.input)
                        if self._verbose:
                            print(f'[tool] {tool_use.name}({tool_use.input}) → {result_content[:120]}')

                tool_results.append({
                    'type':        'tool_result',
                    'tool_use_id': tool_use.id,
                    'content':     result_content,
                })

            # Append tool results as a user turn
            messages.append({'role': 'user', 'content': tool_results})

            if done_result is not None:
                return self._build_result(
                    func_addr, task, done_result, tool_call_count, finished=True
                )

        # Budget exhausted — extract best available answer from last assistant text
        return self._build_result(
            func_addr, task,
            self._extract_partial(messages),
            tool_call_count,
            finished=False,
        )

    # ── patch analysis variant ────────────────────────────────────────────────

    def run_patch(
        self,
        func_addr_v1: int,
        func_addr_v2: int,
        disasm_v1:    str,
        disasm_v2:    str,
        version_v1:   str,
        version_v2:   str,
    ) -> AnalysisResult:
        """Compare two function versions. Returns patch characterization in vuln_notes."""
        prior = self._retrieve_prior(func_addr_v1, callees=None, role_hint='')

        prompt = self._ctx.patch_prompt(
            func_addr_v1, func_addr_v2,
            disasm_v1, disasm_v2,
            version_v1, version_v2,
            prior_findings=prior,
        )
        system_prompt = self._ctx.system_prompt()
        messages = [{'role': 'user', 'content': prompt}]

        # Single-shot for patch analysis — no tool loop needed (disasm already injected)
        response = self._call_claude(system_prompt, messages)
        messages.append({'role': 'assistant', 'content': response.content})

        # Extract tool call if model used done()
        for block in response.content:
            if block.type == 'tool_use' and block.name == 'done':
                return self._build_result(func_addr_v1, 'patch_analysis', block.input, 1, True)

        return self._build_result(
            func_addr_v1, 'patch_analysis',
            self._extract_partial(messages), 1, False
        )

    # ── Claude API call ───────────────────────────────────────────────────────

    def _call_claude(self, system: str, messages: list) -> anthropic.types.Message:
        return self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            system=system,
            tools=TOOL_SCHEMAS,
            tool_choice={'type': 'auto'},
            messages=messages,
        )

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

    @staticmethod
    def _call_signature(tool_name: str, args: dict) -> str:
        """Stable hash of a tool call for loop detection."""
        canonical = json.dumps({'t': tool_name, 'a': args}, sort_keys=True)
        return hashlib.md5(canonical.encode()).hexdigest()

    @staticmethod
    def _extract_partial(messages: list) -> dict:
        """
        Pull a best-effort result from the last assistant message
        when the loop ends without a done() call.
        """
        for msg in reversed(messages):
            if msg.get('role') != 'assistant':
                continue
            for block in (msg.get('content') or []):
                text = getattr(block, 'text', None)
                if text:
                    return {
                        'name':       'unknown__budget_exhausted',
                        'role':       'UNKNOWN',
                        'confidence': 0.1,
                        'rationale':  text[:500],
                        'vuln_notes': '',
                    }
        return {
            'name':       'unknown__no_response',
            'role':       'UNKNOWN',
            'confidence': 0.0,
            'rationale':  'No analysis produced',
            'vuln_notes': '',
        }

    def _build_result(
        self,
        func_addr:  int,
        task:       str,
        done_args:  dict,
        tool_calls: int,
        finished:   bool,
    ) -> AnalysisResult:
        return AnalysisResult(
            func_addr=func_addr,
            name=done_args.get('name', ''),
            role=done_args.get('role', 'UNKNOWN'),
            confidence=float(done_args.get('confidence', 0.0)),
            rationale=done_args.get('rationale', ''),
            vuln_notes=done_args.get('vuln_notes', ''),
            tool_calls=tool_calls,
            finished=finished,
            model=self._model,
            task=task,
        )

    # ── result persistence ────────────────────────────────────────────────────

    def persist_result(self, result: AnalysisResult, binary_sha256: str):
        """
        Write an AnalysisResult back into func_id_db as ANGR_INFERRED confidence.
        Only persists if confidence >= 0.5 and a name was produced.
        """
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
                notes=f'LLM-inferred ({result.model}, {result.tool_calls} tool calls). {result.rationale[:200]}',
            ))
        except Exception:
            pass   # binary may not be registered; silent skip
