# Agent Configuration for Reverse Engineering

Ablation can be used with terminal and IDE coding agents. This guide provides a common reverse-engineering workflow and links to agent-specific configuration. Model names and available permission modes can change; use the strongest coding or reasoning model available in your installed version.

## Shared setup

Install Ablation and start the agent from the repository root:

```bash
pip install ablation-tool
cd ~/ablation
```

Use an isolated analysis environment, preserve original artifacts, and write extracted files and reports to a separate working directory. Keep command approval and sandbox protections enabled unless an isolated environment provides equivalent controls.

A portable objective that works in any agent:

```text
Reverse engineer [target binary, firmware image, or directory]. Preserve the
original artifacts. Identify the architecture, format, and entry points first.
Use Ablation to build the corpus, sweep for candidates, and inspect promising
functions with CFG and taint analysis. Record evidence for each finding and
validate the final results.
```

## Moonshot AI Kimi

Launch from the repository root:

```bash
cd ~/ablation && kimi
```

Recommended settings:

- Select K3.1 Pro or the strongest available K3-family model.
- Use maximum thinking effort for unfamiliar architectures and difficult analysis; use high effort for routine work.
- Use automatic permissions for a trusted local workspace and manual permissions for sensitive systems.
- Keep the dangerous-command guard enabled.

Follow the [Kimi Code reverse-engineering configuration](../kimi-code-configuration.md) for the complete `config.toml` and `tui.toml` profile.

## Anthropic Claude Code

Launch and select the model:

```bash
cd ~/ablation && claude
```

```text
/model claude-sonnet-4-6
/goal reverse engineer [target binary, firmware image, or directory]
/btw What effort level should we be set on right now?
```

Recommended autonomous configuration (`/config`):

```text
Model                                   claude-sonnet-4-6
Thinking mode                           true
Auto-compact                            true
Continue automatically at usage limit   true
Dynamic workflows                       true
Dynamic workflow size                   unrestricted
Rewind code (checkpoints)               true
Use auto mode during plan               true
Default permission mode                 Manual
Respect .gitignore in file picker       true
Verbose output                          true
Output style                            Explanatory
Question auto-continue timeout          never
```

See [Using Ablation with Claude Code](claude-code.md) for the complete CLI workflow and `CLAUDE.md` template.

## OpenAI Codex

Launch from the repository root:

```bash
cd ~/ablation && codex
```

Recommended settings:

- Use `/model` to select the strongest available coding model and a high reasoning effort for deep analysis.
- Use `/permissions` to select workspace-limited write access and retain approval for commands that cross the workspace boundary.
- Run `/init` if the repository needs an `AGENTS.md`, then add target-specific tools, architectures, output paths, and validation commands.
- Use Plan mode before large code changes or irreversible analysis workflows.

See the official [Codex CLI documentation](https://developers.openai.com/codex/cli/).

## Google Antigravity and Gemini

For Antigravity CLI, launch from the repository root:

```bash
cd ~/ablation && agy
```

You can also open the repository in the Antigravity IDE. Existing Gemini CLI installations can be started with `gemini` instead.

Recommended settings:

- Prefer Antigravity for the latest Gemini models; Google notes that Gemini CLI is not optimized for its newest models.
- Select the strongest available Gemini coding or reasoning model.
- Keep sandboxing, trusted-folder controls, and command confirmations enabled.
- Use the context-file mechanism supported by your installed version to record target-specific commands and constraints.

See the official [Antigravity site](https://antigravity.google/) and [Gemini CLI repository](https://github.com/google-gemini/gemini-cli).

## OpenCode

Launch from the repository root:

```bash
cd ~/ablation && opencode
```

Recommended settings:

- Run `/connect` to configure a provider, then select the strongest available coding or reasoning model.
- Run `/init` if the repository needs an `AGENTS.md` for project instructions.
- Use Tab to enter Plan mode before large edits; return to Build mode only after reviewing the plan.
- Keep write and shell permissions set to ask unless the analysis environment provides equivalent isolation.

See the official [OpenCode documentation](https://opencode.ai/docs/).

## Hermes Agent

Configure the provider and tools, then launch from the repository root:

```bash
cd ~/ablation
hermes model
hermes tools
hermes
```

Recommended settings:

- Select the strongest available coding or reasoning model.
- Enable the file and terminal tools needed for Ablation, while retaining command approval.
- Use a Docker, SSH, or other isolated terminal backend when analyzing untrusted artifacts.
- Review persistent-memory and automatic skill-creation settings before analyzing sensitive targets.

See the official [Hermes Agent documentation](https://hermes-agent.nousresearch.com/docs) and [source repository](https://github.com/NousResearch/hermes-agent).

## Shared Ablation workflow

Run these commands through the agent's normal shell or command mechanism:

```bash
ablation corpus /path/to/firmware.so --product my-target --version 1.0
ablation sweep /path/to/firmware.so
ablation search /path/to/firmware.so "parser reads user-controlled length field"
ablation cfg /path/to/firmware.so 0x1fa00 --insns
ablation taint /path/to/firmware.so
ablation findings --json session_findings.json
```

Treat automated matches as candidates, not confirmed vulnerabilities. Confirm reachability, data flow, mitigations, and impact with function-level evidence before reporting a finding.
