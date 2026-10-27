"""Shared, single-call transport for Ablation investigation engines."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Callable, Optional


_MODEL_FOR_TASK = {
    "name_function": "claude-haiku-4-5",
    "struct_reconstruct": "claude-haiku-4-5",
    "vuln_hypothesis": "claude-sonnet-4-6",
    "patch_analysis": "claude-sonnet-4-6",
    "exploit_chain": "claude-opus-4-7",
}
_DEFAULT_TASK_MODEL = "claude-sonnet-4-6"
_DISALLOWED_TOOLS = "Bash,Edit,Write,MultiEdit,WebSearch,WebFetch,Workflow,Agent,Task"


@dataclass(frozen=True)
class TransportResponse:
    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0


class AblationTransport:
    """Send one prompt to the configured model and return its text response."""

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        sdk_client=None,
        cli_runner: Optional[Callable] = None,
        timeout: int = 120,
        verbose: bool = False,
    ):
        self._model = model
        self._api_key = api_key
        self._sdk_client = sdk_client
        self._cli_runner = cli_runner or self._run_cli
        self._timeout = timeout
        self._verbose = verbose

    def model_for_task(self, task: str) -> str:
        return self._model or _MODEL_FOR_TASK.get(task, _DEFAULT_TASK_MODEL)

    def complete(
        self,
        system: str,
        prompt: str,
        task: str = "vuln_hypothesis",
        model: Optional[str] = None,
        max_tokens: int = 1024,
    ) -> TransportResponse:
        if not system.strip() or not prompt.strip():
            raise ValueError("system and prompt must be nonempty")
        if max_tokens < 1 or max_tokens > 8192:
            raise ValueError("max_tokens must be between 1 and 8192")
        selected = model or self.model_for_task(task)
        if self._sdk_client is not None or self._api_key or os.environ.get("ANTHROPIC_API_KEY"):
            return self._call_sdk(system, prompt, selected, max_tokens)
        return self._call_cli(system, prompt, selected, max_tokens)

    def _call_sdk(self, system: str, prompt: str, model: str, max_tokens: int) -> TransportResponse:
        client = self._sdk_client
        if client is None:
            import anthropic

            client = anthropic.Anthropic(api_key=self._api_key or os.environ["ANTHROPIC_API_KEY"])
        if self._verbose:
            print(f"[ablation.transport] sdk model={model} prompt_len={len(prompt)}")
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(getattr(block, "text", "") for block in message.content).strip()
        if not text:
            raise RuntimeError("model returned empty content")
        usage = message.usage
        return TransportResponse(text, model, usage.input_tokens, usage.output_tokens)

    def _call_cli(self, system: str, prompt: str, model: str, max_tokens: int) -> TransportResponse:
        del max_tokens
        cmd = [
            "claude", "-p", "-",
            "--output-format", "json",
            "--system-prompt", system,
            "--disallowedTools", _DISALLOWED_TOOLS,
            "--model", model,
        ]
        if self._verbose:
            print(f"[ablation.transport] cli model={model} prompt_len={len(prompt)}")
        with tempfile.TemporaryDirectory() as cwd:
            proc = self._cli_runner(cmd, prompt, cwd, self._timeout)
        if proc.returncode != 0:
            raise RuntimeError(f"claude CLI exit {proc.returncode}: {(proc.stderr or proc.stdout)[:300]}")
        text = proc.stdout.strip()
        if not text:
            raise RuntimeError("claude CLI returned empty output")
        try:
            events = json.loads(text)
        except json.JSONDecodeError:
            return TransportResponse(text, model)
        if isinstance(events, dict):
            events = [events]
        if not isinstance(events, list):
            raise RuntimeError("claude CLI returned an invalid event envelope")
        result = next((event for event in events if isinstance(event, dict) and event.get("type") == "result"), None)
        if result is None:
            raise RuntimeError("claude CLI output has no result event")
        if result.get("is_error"):
            raise RuntimeError(f"claude CLI is_error=true: {result.get('result', '')[:300]}")
        response = str(result.get("result", "")).strip()
        if not response:
            raise RuntimeError("claude CLI returned an empty result")
        return TransportResponse(response, model)

    @staticmethod
    def _run_cli(cmd: list[str], prompt: str, cwd: str, timeout: int):
        return subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
