# Persistence & Isolation

## Purpose

**Project memory** makes an investigation resumable without treating an AI Agent's chat history as a database. GEM records the target, discoveries, selections, bookmarks, terminal directories, and preferences in the project directory. The human can return to the same Lab and direct new work from the recorded state.

## Session files

A typical project contains:

| File | Purpose |
|---|---|
| `session.json` | Target path, file/directory kind, identity, creation time, and optional terminal workspace |
| `project.json` | Saved active Lab, Lab session locations, terminal directories, and selected nodes |
| `events.jsonl` | Append-only discovery history for Lab #1 |
| `state.json` | Current selection and bookmark IDs |
| `preferences.json` | Layout, terminal font, color scheme, and ANSI palette |
| `AGENTS.md` | Agent instructions, evidence rules, and session-specific commands |
| `bin/gem` or `bin/gem.cmd` | Session-local CLI wrapper used by the embedded agent |
| `investigations/0002/` | Independent Lab #2 with the same session-file structure |

The project is a set of authoritative session files, not a copied AI conversation or a duplicate analysis-results database.

## Saving a project

**Save project** writes the current preferences and a project manifest. The manifest records the active Lab, Lab session paths, terminal directories, and selected nodes. Selection state and the manifest are written atomically. Discoveries and selections are already persisted during normal work, so saving does not rewrite their history.

Closing the application saves the project automatically. The explicit Save action is useful when the user wants confirmation before pausing or switching tasks.

Each Lab has its own events and state. GTK Lab #1 uses the root session; numbered Labs use `investigations/0002`, `investigations/0003`, and so on. Root preferences are shared intentionally, while investigation histories remain independent.

## Resuming a project

Use the same target and session directory:

```bash
gem lab /path/to/target --session /path/to/project --agent kimi
```

On native Windows and macOS, add `--toolkit tk`. Use this same explicit target-and-session command to resume a project after opening GEM.

The target identity must match the session. A file session uses a full content SHA256; a directory session uses an identity based on its absolute path, not a claim about directory content. Reusing a session for a different target is rejected. The project directory must be outside the RE target directory.

## What is restored

- Event history and the current node for each Lab.
- Selected nodes and bookmarks.
- Terminal working directories, with a warning and fallback when a saved directory no longer exists.
- The active Lab and saved Lab tabs where supported.
- Layout, terminal font, color scheme, and ANSI palette preferences.
- Explicit review states, evidence paths, scope, and notes.

A saved terminal directory does not change the RE target. The command-line `--workspace` option can override it explicitly.

## What is not serialized as memory

- The live agent process or its model context.
- The full terminal scrollback or a guarantee of provider-side conversation restoration.
- The target artifact itself or a recursive inventory of its contents.
- Automatic vulnerability verdicts or proof of analysis coverage.
- Credentials, model-provider configuration, or an AI model.

The recorded Lab history and current selection are the supported continuation state. A new agent must inspect the session and supporting evidence rather than assume a previous conversation is complete.

## Consistency and corruption handling

Event reads use shared locks, writes use exclusive locks, and initialization uses a separate lock. Selection state and preferences are written through temporary files followed by atomic replacement. Identical event replay is a no-op, and event cycles are rejected.

Corrupt session files produce visible workspace or restoration errors. Corrupt preferences are reported rather than silently replaced; applying Preferences is an explicit save. A missing selected node falls back to the root artifact instead of leaving an invalid selection.

## Implementation map

- `gem-lab/gem/events.py`: session metadata, event history, selection, project manifest, and persistence
- `gem-lab/gem/preferences.py`: terminal preference loading and atomic saving
- `gem-lab/gem/layout.py`: workspace-layout validation and persistence
- `gem-lab/gem/gtk_app.py`: Lab restoration, active-Lab saving, and close-time persistence
- `gem-lab/gem/app.py`: Tk project saving and restoration

## Validation

Tests cover selection restoration, bookmarks across selection and reopen, active-Lab restoration, terminal-directory fallback, independent investigation histories, corrupt metadata and state files, failed atomic writes, and repeated shutdown. The project-saving path is also exercised by the native Windows and macOS application tests.
