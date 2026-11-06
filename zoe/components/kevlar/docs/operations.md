# Kevlar Operator Guide

Kevlar is a stdio proxy firewall for Model Context Protocol servers. It sits between an MCP client and an MCP server, sanitizes model-bound content, and applies egress data-loss prevention to outbound tool calls.

Use this guide to install and operate Kevlar. For protocol internals, scoring arithmetic, and log fields, see [Architecture](architecture.md).

## Requirements and installation

Kevlar requires Python 3.10 or newer on Linux or macOS. It uses only the Python standard library at runtime.

Create an isolated environment from a source checkout:

```bash
git clone https://github.com/Ablation-Tool/kevlar.git
cd kevlar
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
kevlar --help
```

Do not install Kevlar globally merely to simplify an MCP client configuration. Use the executable's absolute path when configuring a client.

## Command syntax

```text
kevlar [--mode strict|lenient|audit] [--log PATH] -- <server-command> [args...]
```

The `--` separator is important. Everything after it belongs to the wrapped MCP server, not to Kevlar.

Examples:

```bash
# Wrap a filesystem server in strict mode
kevlar --mode strict -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Profile a server and record policy decisions
kevlar --mode audit --log /tmp/kevlar.jsonl -- uvx mcp-server-git
```

Kevlar uses stdin and stdout as the MCP protocol channel. Logs go to stderr and, when requested, the JSONL audit file. Do not redirect stdout into a log file while an MCP client is using it.

## Choose a mode

| Mode | Behavior | Recommended use |
|:---|:---|:---|
| `audit` | Sanitizes content but never blocks based on score | Initial profiling and understanding a server's behavior |
| `lenient` | Quarantines from score 30 and rejects from score 80 | Environments that can tolerate fewer enforcements and more potential exposure |
| `strict` | Quarantines from score 10, rejects from score 40, and locks the tool registry | Production use after reviewing the server and its operational requirements |

Start with `strict` only when you already understand the server. Otherwise:

1. Run the server in `audit` mode with a log destination you can protect.
2. Review which tools, content types, and indicators appear.
3. Check whether the server depends on dynamic tool-list changes. Strict mode intentionally blocks them.
4. Switch to the least permissive enforcement mode that meets your requirements.

Mode selection does not replace review of the MCP server itself. Kevlar is a pattern-based control, not proof that a server is safe.

## Configure an MCP client

Activate Kevlar's virtual environment and resolve the executable before editing client configuration:

```bash
. .venv/bin/activate
command -v kevlar
```

Use that absolute path as the client command. Include Kevlar's mode, optional log path, `--`, the server command, and the server's allowed directories or other arguments.

### Claude Desktop on macOS

The usual configuration file is:

```text
~/Library/Application Support/Claude/claude_desktop_config.json
```

Example:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/absolute/path/to/kevlar",
      "args": [
        "--mode", "strict",
        "--log", "/tmp/kevlar-filesystem.jsonl",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/Users/you/Documents"
      ]
    }
  }
}
```

### Claude Desktop or another MCP client on Linux

Use the configuration location documented by your installed client. Do not assume the macOS path. The JSON structure is the same, but the executable and allowed-directory paths must be valid Linux paths.

For example, a Linux filesystem entry can use:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/absolute/path/to/kevlar",
      "args": [
        "--mode", "audit",
        "--log", "/tmp/kevlar-filesystem.jsonl",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/home/you/Documents"
      ]
    }
  }
}
```

Restart the client after changing configuration. Keep the original server configuration available so you can compare behavior and restore it if necessary.

## Read and protect audit logs

Use `--log PATH` to append one JSON object per policy decision. The log includes event type, message ID, mode, score, disposition, and indicator details. See [Audit log fields](architecture.md#audit-log).

Logs can reveal tool names, paths, content snippets, and security-relevant behavior. Patterns marked for masking have masked value snippets, but that does not make an entire log safe to publish.

- Store logs in a directory with appropriate access controls.
- Do not put API keys or other credentials in server commands.
- Do not attach raw logs to public issues.
- Review retention and deletion requirements for your environment.
- Keep stdout dedicated to MCP messages; inspect stderr separately when debugging.

A log entry is evidence of a policy decision, not proof that the flagged content was malicious or that unflagged content was safe.

## Troubleshooting

### The client cannot start Kevlar

Confirm Python 3.10 or newer, activate the correct virtual environment, and run `kevlar --help`. Use the absolute executable path in client configuration. Check that the client is available on Linux or macOS, not an unsupported platform.

### The wrapped server does not start

Test the server command independently, without Kevlar. Confirm that `npx`, `uvx`, and the server package are available and that the `--` separator appears before the server command. Review stderr for the server's own error messages.

### A valid tool call is blocked

Check whether the tool appeared in the sanitized `tools/list` result. Strict mode blocks unknown tools and dynamic registry changes. Also inspect egress DLP indicators; credential-shaped arguments can be rejected even when the tool name is valid.

### Legitimate content is quarantined or rejected

Review the indicator IDs and mode thresholds in the log. Use audit mode to compare behavior without score-based blocking. False positives should be reported with a minimal, non-sensitive reproduction case rather than real credentials or private tool output.

### Messages are rejected as invalid JSON

Kevlar rejects oversized lines, duplicate object keys, NaN/Infinity, non-JSON input, and batch arrays. Verify that the client and server both use newline-delimited MCP stdio messages and that no diagnostic output is being written to protocol stdout.

### The client shows no dynamic tool updates

This is expected in strict mode. `notifications/tools/list_changed` is dropped and the initial sanitized registry remains fixed. Use a different mode only if the server's dynamic behavior is required and understood.

### Child processes remain after shutdown

Kevlar starts the server in a new process group and terminates that group during cleanup. If a process remains, check whether it was started independently of Kevlar or detached itself from the wrapped server's process group.

## Operational limits

- Kevlar wraps stdio MCP servers. It is not an HTTP, SSE, or network firewall.
- Pattern coverage cannot prove that all prompt injection or credential exfiltration is detected.
- CDR can change server behavior by removing descriptions and other prose fields.
- Strict mode is incompatible with servers that require dynamic tool registration.
- False positives and false negatives remain possible. Review consequential decisions.
- Kevlar does not provide authentication, authorization, sandboxing, or a secure runtime for the wrapped server.

See [SECURITY.md](../SECURITY.md) for the security model and reporting scope.

## Verification and support

Run the test suite from a development environment:

```bash
python -m pip install -e ".[dev]"
pytest
```

The suite contains 149 policy and proxy tests. Integration tests use real subprocess pairs without requiring a production MCP service.

- [Architecture](architecture.md): protocol routing, CDR, scoring, schemas, and log format
- [CONTRIBUTING.md](../CONTRIBUTING.md): development and indicator-authoring rules
- [SECURITY.md](../SECURITY.md): private vulnerability reporting
- [CHANGELOG.md](../CHANGELOG.md): release history
