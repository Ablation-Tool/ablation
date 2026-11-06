# Changelog

## [Unreleased]

### Fixed
- `_sanitized_tool_names` was populated before the reject branch cleared the tool list in `_handle_tools_list`. Calls to tools from a rejected list were incorrectly allowed past the name-check. Names are now set after disposition is applied.
- `_parse_strict` bracket pre-screen counted total brackets rather than nesting depth, causing legitimate servers with many tools or complex schemas (anyOf, oneOf) to be rejected. Replaced with `RecursionError` handling on `json.loads`.
- `_redact_blocks` did not redact injection in `resource`-typed content blocks. Also fixed: substitution now runs on `normalize()`d text so unicode-bypass attempts are redacted as well as detected.
- `TAG_CMD_SUBSTITUTION` in description patterns matched markdown backtick quoting (`` `word` ``), causing false positives on legitimate tool descriptions. Now matches only `$()` shell substitution.
- `MCP_TARGET_DOTENV` in description patterns fired on bare `.env file` mentions. Now requires a leading path separator or `~`.
- Late import of `scan_text` and `CONTENT_PATTERNS` inside `_handle_error_response` moved to module-level import.
- Dead `if "description" in result: pass` in `analyze_prompt_get` removed.

### Added
- `pyproject.toml` with `kevlar` CLI entry point. Install with `pip install -e .`, then run `kevlar --mode strict -- <server>`.
- `__all__` in `policy.py` documenting the public API surface.
- `LICENSE` (MIT).
- `SECURITY.md` with vulnerability disclosure instructions.
- `CONTRIBUTING.md` with indicator authoring guide.
- Integration tests: strict-mode egress DLP (two-phase, waits for tools/list before call), `notifications/tools/list_changed` strict-drop and lenient-forward, JSONL audit log field verification.
- Policy unit tests: quarantine redaction for both `text` and `resource` blocks, unicode-bypass redaction, false-positive regression for tightened patterns.

## [0.1.0] — 2026-10-24

Initial release.

- Async stdio proxy (`kevlar.py`) wrapping any MCP server command.
- Pure CDR/indicator engine (`policy.py`), stdlib only, no I/O.
- Modes: `strict`, `lenient`, `audit`.
- CDR coverage: `tools/list`, `tools/call`, `initialize`, `resources/list`, `prompts/list`, `prompts/get`.
- Egress DLP on outbound `tools/call` arguments.
- Indicator registry sourced from MCP cross-server poisoning PoC payloads, WAHH, and Security Engineering.
- 138 tests.
