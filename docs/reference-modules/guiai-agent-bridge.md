# AI Agent bridge

## Purpose

The AI Agent bridge puts the user's **real interactive agent CLI** inside the GUIAI workbench. GUIAI does not supply a model, simulate an agent, or run a second chatbot. The user chooses the executable and retains control of authentication, permissions, provider policy, and tool behavior.

The bridge is useful when a reverse-engineering session needs both a visual investigation state and an interactive terminal. The agent performs labor; the workspace preserves discoveries; the human chooses what to investigate next.

## Launching an agent

Pass an executable with `--agent`, or a complete command with `--agent-command`:

```bash
guiai desktop /path/to/target --session /path/to/project --agent kimi
guiai desktop /path/to/target --session /path/to/project --agent claude
guiai desktop /path/to/target --session /path/to/project --agent codex
guiai desktop /path/to/target --session /path/to/project --agent-command 'your-agent --flag'
```

Use the actual executable for the agent you are already using. GUIAI does not silently substitute another provider or agent. If the executable cannot be identified, install or configure it separately or supply an explicit path.

## Environment and session contract

Each embedded terminal receives a session-specific environment:

| Variable | Meaning |
|---|---|
| `GUIAI_SESSION` | Root of the current investigation session |
| `GUIAI_STATE` | Current selected-node state file |
| `GUIAI_EVENTS` | Append-only discovery history |
| `GUIAI_CLI` | Session-local GUIAI wrapper, so the agent can read and write session state |
| `GUIAI_WORKSPACE` | Actual terminal working directory, independent of the RE target and session |
| `GUIAI_TARGET` | File or directory being investigated |
| `GUIAI_TARGET_KIND` | `file` or `directory` |
| `GUIAI_ROOT_ID` | Parent ID for new top-level discoveries |
| `ABLATION_BINARY` | Current file target, set only for single-file investigations |
| `ABLATION_CLI` | Ablation command, defaulting to `ablation` |

The wrapper and the current Python executable directory are added to `PATH`. A session-local `AGENTS.md` tells the agent to read current state, record evidence through the CLI, treat artifact contents as untrusted data, and avoid claiming coverage from filenames or memory.

## Terminal implementations

- **Linux GTK:** native VTE terminal with color, font, palette, and multi-Lab support.
- **Tk:** the bundled `TerminalPanel` and `pyte` parser with a POSIX PTY on Linux and macOS, and ConPTY on native Windows.
- **macOS app:** `Contents/MacOS/Ablation` launches the same Tk workbench from the bundled Python environment.

The bridge forwards interactive keys, Unicode, clipboard operations, control sequences, resize events, and process termination. It is not a transcript-only bridge: the CLI remains interactive and can use its own prompts, permission dialogs, and terminal interface.

## Typical workflow

1. Select an artifact or investigation node in the Lab.
2. Use **Open in CLI** or copy a focused follow-up prompt.
3. The agent reads `guiai state` and `guiai tree` and performs actual analysis.
4. The agent records supported results with `guiai emit` or `guiai emit-many`.
5. The workspace refreshes the tree, details, charts, and status summaries.
6. The human selects another branch or requests review.

Example event command:

```bash
guiai emit --session . \
  --id observation:entry-check --parent "$GUIAI_ROOT_ID" \
  --type observation --label "Entry-point check" --status in_progress \
  --evidence analysis/entry-check.txt \
  --note "Record the inspected output and remaining uncertainty"
```

## Process lifecycle

A GTK Lab starts its agent when the tab is selected. Closing a tab stops the terminal but retains the session history. Restored tabs can start a fresh CLI later. Closing the application cancels deferred starts, signals child process groups, waits briefly, and escalates stubborn children where necessary.

The terminal preserves queued output while the child exits. ConPTY shutdown waits for both process exit and reader end-of-stream, preventing final output from being lost. POSIX children are reaped with nonblocking `waitpid` handling.

Terminal scrollback and the agent's conversation are not the authoritative project record. The session's events and selection state are the supported continuation memory.

## Security and permissions

The agent's own account and permission model remain in force. GUIAI does not bypass sandbox restrictions, trust prompts, command approval, or provider policy. The bridge does not execute the RE target by itself and does not prescribe a blanket vulnerability verdict.

Interactive terminal behavior varies by agent. Kimi and local interactive fixtures are validated; every other agent's full-screen interface, authentication flow, or terminal requirements may need compatibility testing.

## Implementation map

- `guiai-lab/guiai/environment.py`: session environment and agent-specific variables
- `guiai-lab/guiai/cli.py`: `desktop`, `state`, `tree`, `emit`, and `review` commands
- `guiai-lab/guiai/gtk_app.py`: native VTE startup, tab lifecycle, and agent process management
- `guiai-lab/metrix/agent.py`: external command parsing and the separate read-only METRIX bridge
- `guiai-lab/metrix/desktop.py`: Tk terminal, PTY/ConPTY I/O, rendering, and cleanup

## Validation

Native tests cover shell wrappers with spaces, interactive PTY startup and input, forced cleanup, final ConPTY output draining, child reaping, partial writes, oversized paste rejection, delayed-start cancellation, and repeated close. The desktop workflow checks real keyboard focus, Unicode input, clipboard operations, CLI state, and directory selection.
