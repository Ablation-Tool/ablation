# AgentToolSurfaceEnumerator

## Why this exists

One thing was not possible before in Ablation:

1. **Extract and classify the tool definitions that an LLM agent registers, directly from the binary's rodata.** `AgentAuthorityAudit` checks for capability categories by import table. No prior module extracted the actual tool schema JSON embedded in the binary: the function names, descriptions, and parameter definitions the agent hands to the LLM as its available actions. `AgentToolSurfaceEnumerator` regex-scans the binary for JSON objects containing `"name"` and `"description"` or `"parameters"` keys, extracts each tool name, and classifies it against 6 high-risk capability patterns and 2 medium-risk patterns. This tells an analyst exactly what the LLM can instruct the agent to do.

## Usage

```python
from modules.agent_tool_surface_enumerator import AgentToolSurfaceEnumerator

enumerator = AgentToolSurfaceEnumerator('/path/to/binary')
findings = enumerator.scan()
print(enumerator.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
enumerator = AgentToolSurfaceEnumerator.from_context(ctx)
findings = enumerator.scan()
```

## Output: ToolSurfaceFinding

| Field | Type | Description |
|-------|------|-------------|
| `tool_name` | str | Tool name extracted from JSON schema |
| `capability` | str | Capability class (see table) |
| `severity` | str | `HIGH` or `MEDIUM` |

## Capability classes

| Class | Severity | Matched tool name patterns |
|-------|----------|---------------------------|
| `shell_execution` | HIGH | run, exec, bash, shell, command, execute, cmd, terminal |
| `code_execution` | HIGH | python, javascript, eval, run_code, execute_code, repl |
| `file_write` | HIGH | write_file, create_file, edit_file, delete_file, overwrite |
| `process_control` | HIGH | spawn_process, kill_process, list_processes, start_service |
| `network_request` | HIGH | http_request, fetch_url, send_request, post_to, make_request |
| `credential_access` | HIGH | get_secret, read_credential, get_api_key, retrieve_token |
| `web_search` | MEDIUM | web_search, search_web, google, duckduckgo |
| `file_read` | MEDIUM | read_file, open_file, get_file, load_file |

## Limitations

The regex matches tool-schema JSON in rodata. Tools defined at runtime via dynamic string construction or loaded from external config files will not be found. A clean result does not confirm no dangerous tools exist; it confirms none were found in static string data.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on synthetic JSON blob containing `"name": "bash"`: `shell_execution` HIGH finding emitted.

## See also

- [AgentAuthorityAudit](agent-authority-audit.md): import-table capability excess
- [AgentObservabilityAudit](agent-observability-audit.md): missing audit trail in agentic loops
- [PromptInjectionSinkClassifier](prompt-injection-sink-classifier.md): untrusted input reaching LLM API
