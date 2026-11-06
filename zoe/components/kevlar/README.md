<p align="center">
  <img src="KEVLAR-repo-01.png" alt="Kevlar MCP CDR Proxy" width="480px">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/deps-stdlib_only-brightgreen.svg" alt="stdlib only">
  <img src="https://img.shields.io/badge/runtime-asyncio-lightgrey.svg" alt="asyncio">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-informational.svg" alt="Linux/macOS">
  <img src="https://visitor-badge.laobi.icu/badge?page_id=Ablation-Tool.kevlar" alt="Visitors">
</p>

# Kevlar

Kevlar is a proxy firewall for Model Context Protocol

```
LLM  [ KEVLAR ]  MCP
```

It sits between (you) and (everyone else)

## Why do I need Kevlar?

MCP servers control their own tools. 

Those tools (good or bad) go into your LLM blindly, due to trust.

Any MCP server can exploit this to redirect the model, pull credentials, or add any tools they want. 

The MCP spec does not prevent any of this.

You do not control what an MCP server puts in its messages.

## Capabilities

<details>
<summary>Proxy & Protocol Protection</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Strict Message Validation**](docs/architecture.md#message-routing) | [1](kevlar.py) | Bounds line reads, rejects duplicate keys, NaN/Infinity, and batch arrays, and reserializes every forwarded message. |
| [**Process Lifecycle Control**](docs/architecture.md#proxy-lifecycle) | [1](kevlar.py) | Runs concurrent protocol pumps and terminates the server process group on shutdown to avoid orphaned children. |
| [**Fail-Closed Routing**](docs/architecture.md#message-routing) | [1](kevlar.py) | Routes MCP messages through policy handlers, drops unsupported content, and converts internal failures into protocol errors. |

</details>

<details>
<summary>Content Disarm & Reconstruction</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Tool List CDR**](docs/architecture.md#inbound-toolslist) | [1](policy.py) | Strips tool descriptions and rebuilds tools with sanitized names and schemas before they reach the model. |
| [**Tool Response Analysis**](docs/architecture.md#inbound-toolscall-response) | [1](policy.py) | Scans response content and redacts or rejects injection payloads according to the active mode. |
| [**Initialize, Resource & Prompt CDR**](docs/architecture.md#inbound-initialize) | [1](policy.py) | Strips instructions and descriptions and scans prompt content across additional MCP message types. |
| [**Schema CDR Allowlist**](docs/architecture.md#schema-cdr-allowlist) | [1](policy.py) | Rebuilds input schemas from validated structural fields and drops prose, unsafe references, and excessive nesting. |

</details>

<details>
<summary>Policy & Enforcement</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Mode-Based Scoring**](docs/architecture.md#scoring) | [1](policy.py) | Applies severity weights and strict, lenient, or audit thresholds to allow, quarantine, or reject content. |
| [**Egress DLP**](docs/architecture.md#egress-dlp) | [1](policy.py)&nbsp;[2](kevlar.py) | Scans outbound tool-call arguments and blocks credential-bearing calls before they reach the server. |
| [**Tool Registry Lock**](docs/architecture.md#tool-registry-lock) | [1](kevlar.py) | Freezes callable tool names after the initial handshake and blocks mid-session tool injection in strict mode. |
| [**Indicator Registries**](docs/architecture.md#indicator-registries) | [1](policy.py) | Uses separate aggressive description and conservative content patterns with stable IDs and snippet masking. |

</details>

<details>
<summary>Audit & Extensibility</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**JSONL Audit Log**](docs/architecture.md#audit-log) | [1](kevlar.py) | Records policy decisions, scores, indicators, and masked snippets without writing logs into the protocol channel. |
| [**Pure Policy Engine**](docs/architecture.md#module-overview) | [1](policy.py) | Keeps policy decisions separate from I/O for direct unit testing and reuse in other projects. |

</details>

## Operations

<details>
<summary>Operator Guide</summary>

See [docs/operations.md](docs/operations.md) for client setup on macOS and Linux, mode selection, audit-log handling, troubleshooting, operational limits, and verification commands.

</details>

<details>
<summary>Quickstart</summary>

```bash
kevlar --mode strict -- npx -y @modelcontextprotocol/server-filesystem /tmp
kevlar --mode audit --log /tmp/kevlar.jsonl -- uvx mcp-server-git
```

</details>

<details>
<summary>Claude Desktop integration</summary>

In `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "kevlar",
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

</details>

<details>
<summary>Modes</summary>

| Mode | Reject threshold | Tool registry | `list_changed` |
|------|-----------------|---------------|----------------|
| `strict` | score ≥ 40 | Locked at handshake | Dropped |
| `lenient` | score ≥ 80 | Dynamic updates allowed | Forwarded |
| `audit` | Never blocks | Dynamic | Forwarded |

Use `strict` in production. Use `audit` to profile a new server before tightening the threshold. `--log` produces a JSONL file with every policy decision, indicator ID, score, and masked value snippet.

</details>

## Setup & About

<details>
<summary>AI Agent Install</summary>

```text
Install Kevlar from https://github.com/Ablation-Tool/kevlar for me.

Confirm Linux or macOS with Python 3.10 or newer. Clone the repository if it
is absent. For an existing checkout, verify its origin and check for
uncommitted changes. Do not reset, clean, overwrite, or pull over local
changes. Stop and ask if the remote differs or the checkout is dirty.

Review pyproject.toml and the documented Kevlar entry point. Create a
project-local Python virtual environment, activate it for my shell, and
install from the source checkout with:

  python -m pip install .

Verify with `kevlar --help`. Stop on errors and do not use sudo, global
Python installation, or alternate package sources.

Do not edit Claude Desktop or other MCP client configuration, launch npx or
uvx servers, or place credentials in commands or logs. If I later request a
server profile, propose audit mode first and explain the log destination.
Use strict enforcement only after I approve it. Report the checkout and
environment paths, Python version, and verification result.
```

</details>

<details>
<summary>Manual Install</summary>

```bash
git clone https://github.com/Ablation-Tool/kevlar.git
cd kevlar
pip install .
```

Requires Python 3.10+. Linux and macOS only. Depends on `os.killpg` and `asyncio.connect_read_pipe`.

</details>

<details>
<summary>Architecture</summary>

Two files: `policy.py` is a pure CDR engine with no I/O, directly unit-testable. `kevlar.py` is the async stdio proxy. No runtime dependencies, stdlib only. `kevlar.py` spawns the server with `start_new_session=True` and kills the process group on shutdown, so `npx`/`uvx` child processes don't linger.

See [docs/architecture.md](docs/architecture.md) for the full design: proxy lifecycle, CDR pipeline per message type, scoring arithmetic, indicator registries, and audit log format.

</details>

<details>
<summary>Tests</summary>

```bash
pip install -e ".[dev]"
pytest
```

149 tests. `tests/test_proxy.py` runs integration tests against real subprocess pairs. `tests/test_policy.py` covers the pure policy engine in unit tests.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development rules, [SECURITY.md](SECURITY.md) for private vulnerability reporting, and [CHANGELOG.md](CHANGELOG.md) for release history.

</details>

<details>
<summary>License</summary>

Kevlar is free and open-source software under the [MIT License](LICENSE). You may use, modify, and distribute it, including for commercial purposes, provided the copyright and license notice are retained. The software is provided without warranty.

</details>
