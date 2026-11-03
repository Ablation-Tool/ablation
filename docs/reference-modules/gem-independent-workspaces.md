# Independent Workspaces

## Purpose

Independent workspaces let a researcher investigate multiple targets or terminal directories without mixing their discoveries, selections, or CLI working state. Each GTK Lab pairs an investigation tree with a real agent terminal. The workspace, not the user's memory, tracks which work belongs to which Lab.

## Lab sessions

**Lab #1** uses the root session. The native `+` button asks for a terminal directory before creating `investigations/0002`, `investigations/0003`, and subsequent Labs. Each Lab receives:

- Its own session directory and metadata.
- Its own `events.jsonl` and `state.json`.
- Its own agent instructions and CLI wrapper.
- Its own terminal working directory and agent process.
- Its own selected node, bookmarks, expansion state, and visible history.

Sessions and selection files are never shared between independent Labs. Root preferences such as the chosen layout and terminal palette are shared intentionally so the overall workbench remains consistent.

## Terminal directory, target, and session

These locations have different roles:

- **RE target:** the file or material directory being investigated.
- **Project/session directory:** authoritative GEM history and preferences, kept outside the target.
- **Terminal working directory:** the directory in which a particular agent CLI starts and performs its work.

Choosing another terminal directory does not change the RE target. A command-line `--workspace` option can override saved per-tab directories explicitly. If a saved directory disappears, GEM warns and falls back to the Lab's session directory rather than silently selecting a different target or workspace.

## Lifecycle and restoration

A restored GTK Lab starts its agent when selected, avoiding unnecessary background processes for every restored tab. Closing a tab stops its CLI but retains its session history, so the Lab can be restored on the next launch. Tab labels, pending callbacks, and agent processes are released independently.

The current layout applies to every open Lab without rebuilding its event history or terminal state. Each Lab's tree, chart, details, and terminal remain attached to that Lab when the arrangement changes.

## Using multiple research targets

A typical workflow is:

1. Keep Lab #1 for the primary firmware target.
2. Select `+` and choose a second research directory for Lab #2.
3. Let each agent inspect and emit discoveries through its own session wrapper.
4. Switch tabs to compare the investigation trees without merging their states.
5. Save the project to record the active Lab and resume later.

Independent does not mean isolated from judgment. The user should still check each target's identity, tool permissions, evidence paths, and agent output before treating a result as confirmed.

## Tk boundary

The Tk interface is a **single-investigation** interface on Linux and the native interface on Windows and macOS. It does not provide GTK's multi-Lab notebook. Use a separate project/window when an independent investigation is needed in Tk. The macOS app uses Tk and should not be described as supporting GTK's multi-Lab model.

## Implementation map

- `gem-lab/gem/gtk_app.py`: Lab creation, independent sessions, tab restoration, directory choice, and terminal lifecycle
- `gem-lab/gem/events.py`: independent session metadata, workspace validation, and event history
- `gem-lab/gem/app.py`: single-investigation Tk workspace
- `gem-lab/gem/preferences.py`: root-level preferences shared across Labs

## Validation

Tests cover multiple independent live CLIs, per-tab directory choice, real child working directories, invalid directory rejection, deleted-directory fallback, restoration after closing tabs, command-line workspace overrides, and tab-label/callback cleanup. Repeated tab creation and close checks watch for retained workspaces, duplicate agents, and memory growth.
