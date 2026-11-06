import json
import os
from pathlib import Path
import shlex
import sys
import threading

from gem.agent import AgentError as GemAgentError, invoke_agent


ALLOWED_FILTERS = {"format", "architecture", "artifact_class", "status", "analysis_status"}
MAX_PROMPT_CHARACTERS = 60000
MARKER = "METRIX_JSON="


class AgentError(RuntimeError):
    pass


def parse_agent_command(value):
    if not value:
        return None
    command = shlex.split(value)
    if not command:
        raise ValueError("agent command is empty")
    return command


def kimi_command():
    return ["kimi", "-p", "{prompt}"]


def compact_record(record):
    return {
        key: record.get(key)
        for key in (
            "id", "path", "size_bytes", "sha256", "format", "architecture",
            "endianness", "artifact_class", "status", "analysis_status", "detection", "scan_error",
        )
        if record.get(key) is not None
    }


def build_prompt(message, selected, filters, history, output, workspace):
    context = {
        "output_directory": str(output),
        "workspace": str(workspace),
        "active_filters": filters,
        "selected_artifacts": [compact_record(record) for record in selected],
        "recent_conversation": history,
        "user_message": message,
    }
    context_json = json.dumps(context, ensure_ascii=False, separators=(",", ":"))
    if len(context_json) > MAX_PROMPT_CHARACTERS // 2:
        context["selected_artifacts"] = context["selected_artifacts"][:5]
        context["recent_conversation"] = context["recent_conversation"][-2:]
        context["context_truncated"] = True
        context_json = json.dumps(context, ensure_ascii=False, separators=(",", ":"))
    cli_command = shlex.join([sys.executable, "-m", "metrix"])
    instructions = f"""You are connected to the METRIX dashboard through an external-agent bridge.
You are the user's configured AI agent, not a METRIX model. Help navigate the corpus using evidence.
This request is read-only: do not modify files, execute collected artifacts, or run deeper analysis.
METRIX can be queried with: {cli_command} query --output OUTPUT_DIR [--format VALUE] [--architecture VALUE] [--kind VALUE] [--status VALUE] [--contains TERM].
The matrix supports filters: format, architecture, artifact_class, status, analysis_status, plus free-text search.
Answer the user concisely. Clearly separate observed METRIX facts from your assessments.
If a dashboard action is useful, make the final line exactly one single-line JSON object prefixed by METRIX_JSON= with this shape:
METRIX_JSON={{"message":"your response","action":{{"type":"filter","search":"","filters":{{"format":"unknown"}}}}}}
Omit action when no filter change is useful. Do not invent artifact facts. Do not include credentials in your response.
CONTEXT (JSON):
{context_json}
"""
    if len(instructions) > MAX_PROMPT_CHARACTERS:
        instructions = instructions[:MAX_PROMPT_CHARACTERS - 80] + "\n[Prompt truncated by METRIX bridge]\n"
    return instructions


def parse_response(raw):
    lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("• "):
            stripped = stripped[2:].strip()
        lines.append(stripped)
    normalized = "\n".join(lines)
    marker_position = normalized.rfind(MARKER)
    if marker_position < 0:
        return {"message": raw.strip() or "Agent returned no text.", "action": None}
    payload = " ".join(normalized[marker_position + len(MARKER):].splitlines()).strip()
    try:
        parsed, _ = json.JSONDecoder().raw_decode(payload)
    except json.JSONDecodeError:
        return {"message": raw.strip(), "action": None, "warning": "Agent returned an invalid METRIX_JSON action."}
    if not isinstance(parsed, dict) or not isinstance(parsed.get("message"), str):
        return {"message": raw.strip(), "action": None, "warning": "Agent action lacked a message."}
    action = parsed.get("action")
    if action is None:
        return {"message": parsed["message"], "action": None}
    if not isinstance(action, dict) or action.get("type") != "filter":
        return {"message": parsed["message"], "action": None, "warning": "Agent action type was not supported."}
    filters = action.get("filters", {})
    search = action.get("search", "")
    if not isinstance(filters, dict) or not isinstance(search, str) or set(filters) - ALLOWED_FILTERS:
        return {"message": parsed["message"], "action": None, "warning": "Agent action contained unsupported filters."}
    if not all(isinstance(value, str) for value in filters.values()):
        return {"message": parsed["message"], "action": None, "warning": "Agent filter values were not strings."}
    return {"message": parsed["message"], "action": {"type": "filter", "search": search, "filters": filters}}


class AgentBridge:
    def __init__(self, command, output, workspace, timeout=180):
        self.command = list(command) if command else None
        self.output = Path(output)
        self.workspace = Path(workspace)
        self.timeout = timeout
        self.executable = Path(self.command[0]).name if self.command else None
        self._lock = threading.Lock()

    @property
    def configured(self):
        return self.command is not None

    def public_state(self):
        return {
            "configured": self.configured,
            "executable": self.executable,
            "mode": "external-cli",
            "interactive": False,
            "data_sent": "chat, active filters, recent chat, and explicitly selected artifact records",
            "permissions": "The external agent's own CLI permissions and provider data policy apply.",
        }

    def ask(self, message, selected, filters, history):
        if not self.configured:
            raise AgentError("No agent is configured. Restart METRIX GUI with --agent kimi or --agent-command.")
        prompt = build_prompt(message, selected, filters, history, self.output, self.workspace)
        environment = os.environ.copy()
        package_root = str(Path(__file__).resolve().parent.parent)
        environment.update({
            "METRIX_OUTPUT": str(self.output),
            "METRIX_WORKSPACE": str(self.workspace),
            "METRIX_READ_ONLY_REQUEST": "1",
            "METRIX_CLI": shlex.join([sys.executable, "-m", "metrix"]),
            "PYTHONPATH": package_root + (os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""),
        })
        with self._lock:
            try:
                result = invoke_agent(
                    self.command, prompt, timeout=self.timeout,
                    cwd=self.workspace, environment=environment,
                )
            except GemAgentError as error:
                raise AgentError(str(error)) from error
        response = parse_response(result["stdout"])
        response.update({
            "agent": self.executable,
            "exit_code": result["returncode"],
            "raw": result["stdout"],
            "stderr": result["stderr"],
        })
        return response
