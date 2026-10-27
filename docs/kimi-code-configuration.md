# Kimi Code Configuration for Reverse Engineering

This profile configures [Kimi Code](https://github.com/MoonshotAI/kimi-code) for reverse engineering, firmware analysis, vulnerability research, and substantial coding tasks. It favors analysis quality, long-running local tools, and preservation of command safeguards.

The configuration contains no credentials, OAuth entries, or machine-specific paths.

## Prerequisites

1. Install Kimi Code and authenticate with `/login`.
2. Confirm that the `kimi-code/k3.1-pro` model alias is available in your configuration. If it is not available, select another K3-family alias exposed by your account and update `default_model` accordingly.
3. Back up your existing configuration before merging this profile.

Kimi Code stores user configuration in `$KIMI_CODE_HOME/config.toml`. When `KIMI_CODE_HOME` is unset, the default location is `~/.kimi-code/config.toml`.

## Runtime configuration

Merge the following keys into `config.toml`. Update existing sections rather than adding duplicate TOML tables. Preserve your existing `providers`, `models`, `services`, and authentication entries.

```toml
# Use the full-capability model for the primary agent.
default_model = "kimi-code/k3.1-pro"

# Balance unattended analysis with command safeguards.
# Use "manual" for sensitive systems or untrusted analysis environments.
default_permission_mode = "auto"
default_plan_mode = false

[thinking]
enabled = true
# Use "high" for routine work when lower latency or usage is preferred.
effort = "max"
keep = "all"

[loop_control]
max_attempts_per_step = 10
# Compact before long RE sessions exhaust the context window.
reserved_context_size = 50000

[task]
# Adjust for available CPU, memory, and analysis-tool licenses.
max_running_tasks = 4
keep_alive_on_exit = false
bash_auto_background_on_timeout = true
# Long extractions and analysis jobs get one hour by default.
# Explicit per-command timeouts still take precedence.
bash_task_timeout_s = 3600

[permission]
# Keep confirmations for dangerous commands and sensitive paths.
dangerous_command_guard = true

[read]
default_max_chars = 100000
max_chars = 500000
```

Leave `[secondary_model]` unset when analysis quality is the priority. Subagents then inherit the caller's model. Configure a separate high-speed secondary model only for routine searches, summaries, and low-risk coding subtasks.

## Terminal UI configuration

Optionally merge these settings into `tui.toml` in the same configuration directory:

```toml
theme = "auto"
tui_mode = "regular"
cache_expiry_hint = true

[notifications]
enabled = true
notification_condition = "unfocused"

[status_line]
items = ["mode", "goal", "model", "tasks", "cwd", "git"]
```

## Validate and apply

Validate the merged runtime configuration without starting the terminal UI:

```bash
kimi doctor config ~/.kimi-code/config.toml
kimi doctor tui ~/.kimi-code/tui.toml
```

If `KIMI_CODE_HOME` is set, replace `~/.kimi-code` with that directory.

Apply the changes with `/reload` in Kimi Code, or start a new session. `/reload` reloads both configuration files and is available only while the session is idle.

## Recommended use

- Use `effort = "max"` for unfamiliar instruction sets, decompilation recovery, protocol reconstruction, and difficult root-cause analysis. Switch to `"high"` for routine implementation and triage.
- Keep `default_permission_mode = "manual"` when working on production systems, live devices, or directories containing valuable data.
- Do not disable the dangerous-command guard merely to reduce prompts.
- Analyze firmware and executables in an isolated environment. Do not execute unknown binaries on the host simply because sandbox tooling is unavailable.
- Keep original artifacts unchanged, record their hashes, and direct extracted or generated files into a separate working directory.
- Prefer targeted searches, function-level disassembly, and structured tool output over loading entire binaries or massive logs into context.
- Add project-specific tool paths, architectures, build commands, test commands, output directories, and safety constraints to the project's `AGENTS.md`.

## Reference

See the official [Kimi Code configuration reference](https://moonshotai.github.io/kimi-code/en/configuration/config-files.html) for all supported fields and defaults.
