# GUIAI Lab

GUIAI Lab is the **native workbench included with Ablation** for agent-guided reverse-engineering sessions. Its visible application name is **Ablation**; the GUIAI package, CLI wrapper, and session protocol retain their names for compatibility. The distribution also includes the METRIX support package, so no separate METRIX checkout is required.

The user’s real interactive CLI supplies labor. The workspace supplies memory and navigation. The human supplies direction and judgment. GUIAI supports any interactive agent executable through `--agent`, and custom argument lists through `--agent-command`; it provides no model or credentials.

For how this improves investigation throughput without making analysis computation faster, see [GUIAI performance and investigation memory](https://github.com/Ablation-Tool/ablation/blob/master-gem-brain/docs/reference-modules/guiai-performance.md).

## What the workbench does

- Embeds the actual interactive agent CLI in a native VTE terminal beside each investigation tree, with guarded startup, duplicate prevention, and explicit failure handling.
- Accepts a single binary or a material directory, with real top-level directory inventory.
- Shows an agent-grown investigation tree with **Lab** and **Status** columns, clickable breadcrumbs, and Up/Home navigation. **Type** appears only when matching rows have different types. Human-readable status and type labels preserve the raw CLI values. Long Lab names use middle ellipsizing with full-name/path tooltips.
- Offers optional **Rings** and **Treemap** visualizations beside the authoritative tree. Treemap area and ring angle both represent subtree node count, not bytes or analysis coverage. Both use Ubuntu Baobab's position/depth palette; status remains explicit text rather than being encoded by tile color. Treemap retains pagination, and Rings adapts Baobab's concentric-sector geometry. Both share selection, breadcrumbs, and `state.json` with the CLI. Rings supports click-to-inspect, center-to-go-up, tooltips, keyboard navigation, and scroll-controlled depth, and reports nodes omitted by angular or depth limits.
- Tracks not-started, in-progress, partial, blocked, reviewed, scoped-complete, rejected, and not-applicable work without merging distinct states or deriving a parent's own status from its children.
- Filters the tree by status or text while retaining ancestor context. Clickable footer status counts apply the corresponding filter, and the complete breakdown remains available below the workspace.
- Shares each investigation's selected node with its corresponding CLI through its own `state.json`. Row-level stars are bookmarks, not review states; they persist in the same state file and can be changed from the tree or the selected-node action.
- Creates paired **Lab #N** tabs with the native `+` button. Every tab has an independent session, event history, selection, stars, and real CLI.
- Restores saved investigation tabs and the active Lab on startup. **Save project** records the project manifest and preferences; discovery history and selections are saved continuously. Restored CLIs start when their tab is selected; closing a tab stops its CLI but retains its history and releases the tab label, workspace, and pending callbacks.
- Keeps one configurable workspace with an optional chart beside the Lab tree. The Lab and terminal can be side by side or stacked in either order. The outer and chart dividers remain adjustable. Node actions remain visible and compact to icons at narrow widths without wrapping. **Node details** uses Vanilla show/hide eye icons and a height-bounded native disclosure, so expanded metadata cannot push actions or the status summary off-screen.
- Uses Ubuntu's native GTK notebook, tree, disclosure, action, and VTE terminal model when available, with official Vanilla Framework icons. The Tk interface remains a single-investigation fallback on Linux and the native interface on Windows and macOS.
- Uses the configured Ubuntu interface and system monospace fonts with native theme text colors in light and dark modes. Tree statuses remain explicit text rather than depending on hard-coded gray or status colors.
- Uses theme-derived alternating row shading and theme-colored icons while preserving native selection colors.
- Offers native terminal schemes, editable foreground/background and all 16 ANSI palette colors, and a terminal font selector through **Preferences**. Four numbered visual previews select the Lab/terminal arrangement without text-heavy options. Lab, Workspace layout, Terminal, and ANSI palette use independent collapsed disclosure sections in GTK; Tk presents a compact graphical layout dialog. Preferences apply to all open Labs and persist in the root session.
- Provides scrollbars, directory rescanning, and a selection-specific follow-up prompt.
- Offers **Show in file manager** to reveal selected evidence in Nautilus, Finder, or Windows Explorer after an explicit user action; it does not execute artifacts.
- Keeps **Open in CLI** as the primary node action, with **Flag for follow-up**, **Mark as reviewed**, and an overflow menu for copy/file-manager actions. Status feedback offers Undo, which appends a restoration event rather than deleting or rewriting history.
- Preserves append-only discovery histories in each investigation's `events.jsonl`.
- Uses the existing Ablation CLI without changing its source.

There is no browser, fake built-in AI, separate chatbot protocol, or automatic blanket vulnerability verdict.

## Architecture

```text
Lab #N                           Native Ablation workbench (Tk fallback)
      │                                  │
      ├─ guiai emit ───────────────► events.jsonl
      │                                  │
      └─ guiai state ◄─────────────── state.json
                                         │
                          Paired tree + real CLI in a tab
```

Each event log is authoritative for its investigation. The tree is a view of that history, not a second session database. The latest event for an ID determines its current status while older events remain available for audit. Sessions and selection files are never shared between investigation tabs.

The GTK interface uses `Gtk.Application`, `Gtk.Notebook`, `Gtk.TreeStore`, `Gtk.ToggleButton`, `Gtk.Expander`, nested `Gtk.Paned` containers, `Gio.SimpleActionGroup`, GLib timeouts, `Vte.Terminal`, and a native Cairo drawing area for Rings. Native color, font, disclosure, and visual-preview widgets implement preferences. The Tk fallback reuses the bundled METRIX terminal component. Baobab 49.1's geometry and palette are adapted for investigation-node units; see `NOTICE` for attribution.

## Install

Native GTK/VTE requires Linux with X11 and Python 3.10 or newer. Native Windows and macOS packages use Tk with ConPTY or POSIX PTY; see the [platform packages](packaging/README.md). On Ubuntu or Debian:

```bash
sudo apt install python3-venv python3-tk python3-gi python3-cairo python3-gi-cairo gir1.2-gtk-3.0 gir1.2-vte-2.91
git clone https://github.com/Ablation-Tool/ablation.git
cd ablation
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
python -m pip install ./guiai-lab
```

METRIX and `pyte` are included or installed automatically. The Installation Prompt installs the standard Ablation CLI and GUIAI together. The source command above installs GUIAI only; add the full CLI with `python -m pip install -e .` when needed.

Start with the **[all-platform installation guide](INSTALL.md)** or copy the **[Universal OS Installation Prompt](INSTALL-PROMPT.md)** into your agent.

## Start a session

Investigate one binary:

```bash
guiai desktop /path/to/binary \
  --session /path/to/investigation-session \
  --agent kimi
```

Or investigate a material directory with any installed interactive agent:

```bash
guiai desktop /path/to/material-directory \
  --session /path/to/investigation-session \
  --agent AGENT_EXECUTABLE
```

`AGENT_EXECUTABLE` can be `kimi`, `claude`, `codex`, or another executable. For an agent that needs custom arguments:

```bash
guiai desktop /path/to/material-directory \
  --session /path/to/investigation-session \
  --agent-command 'your-interactive-agent-cli --flag'
```

Agent CLIs are installed and configured separately. Their authentication, permissions, trust prompts, provider data policy, and terminal behavior remain their own. GUIAI does not supply a model, API key, or second chatbot. Kimi and local interactive fixtures are validated; other agents may require compatibility testing for their specific terminal interface.

By default, `desktop` selects the native GTK interface when GTK and VTE are available. Use `--toolkit gtk` to require it or `--toolkit tk` to select the Tk fallback explicitly.

The macOS offline installer also creates **Ablation.app**. Its first-run window selects the RE target, project directory, and optional installed AI Agent before opening the Tk workbench. The bundle includes its Python environment and icon and can be moved on the same Mac. `Contents/MacOS/Ablation` accepts the same command-line arguments as `guiai`; `Contents/MacOS/Ablation --self-test` verifies the bundled runtime. The locally created app is not signed or Apple-notarized.

Directory initialization adds the root and its real top-level entries. It does not recurse, hash directory contents, or claim analysis coverage. **Rescan directory** repeats the idempotent top-level inventory; deeper work is recorded by the agent after inspection. A directory's identity is based on its absolute path, not a content digest. Single files retain their full SHA256 identity.

The session must be outside a directory target. A session belongs to one target; reusing it for a different target is rejected. Existing file sessions remain compatible.

In the GTK interface, **Lab #1** uses the root session. The `+` button opens a native folder chooser before creating `investigations/0002`, `investigations/0003`, and so on. The selected folder becomes that tab's terminal working directory and is saved independently in its `session.json`; it does not change the RE target. Each tab has its own agent instructions, wrapper, event log, selection, and terminal directory. Cancelling or rejecting an invalid directory creates no tab. Saved numbered investigations and their directories are restored on startup. If a saved directory no longer exists, that terminal uses its session directory and the window shows a warning. Closing a tab stops its terminal without deleting history, so that investigation is restored on the next launch. The command-line `--workspace` option, when present, overrides saved per-tab directories.

**Save project** writes `project.json` with the active Lab, Lab session locations, terminal directories, and selected nodes, and saves the current preferences. Closing the application saves the project automatically. Reopen it with `guiai desktop TARGET --session SESSION` as usual; the authoritative event logs, selections, and bookmarks were already persisted and are not duplicated into a second database. The live process, terminal scrollback, and AI Agent conversation context are not serialized as project memory. The Lab's recorded discoveries and current selection are the supported continuation state.

The native **Preferences** dialog offers Ubuntu/system, Tango, Linux console, XTerm, Solarized dark/light, high-contrast, and custom terminal colors. Custom editing covers foreground, background, and all 16 ANSI palette entries. The terminal defaults to the configured system monospace font; any font installed by the user can be selected through the native font button. Lab, Workspace layout, Terminal, and ANSI palette are collapsed by default in GTK so users reveal only the controls they need. Four graphical choices place the Lab left, right, above, or below the AI Agent; **1** is the Lab and **2** is the AI Agent. GTK applies the selection with **Apply**, while Tk saves it immediately. Every open Lab keeps its original tree, chart, and terminal widgets. One root preference set applies to all open investigations and is restored on the next launch.

Omit `--agent` and `--agent-command` to use only the investigation tree. Lab #1 starts in its saved terminal directory, or the session directory when none is saved; `--workspace` overrides it. New Labs always ask for a directory. The embedded CLI receives:

- `GUIAI_SESSION` — session directory containing authoritative state
- `GUIAI_WORKSPACE` — this terminal's actual working directory, independent of the session and RE target
- `GUIAI_STATE` — selected-node state file
- `GUIAI_EVENTS` — append-only event log
- `GUIAI_CLI` — executable session-local `bin/guiai` wrapper
- `GUIAI_TARGET` — file or directory being investigated
- `GUIAI_TARGET_KIND` — `file` or `directory`
- `GUIAI_ROOT_ID` — root node ID for new discoveries
- `ABLATION_BINARY` — current binary only for a single-file target
- `ABLATION_CLI` — Ablation command, defaulting to `ablation`

The wrapper directory and current Python executable directory are added to the agent's `PATH`, so both `"$GUIAI_CLI"` and `guiai` work as shell commands. The wrapper invokes the current Python interpreter and preserves all arguments; it is not a multiword command string. The agent's command runner must be able to access that interpreter and installed packages. If it uses a sandbox or restricted filesystem, choose an accessible installation location rather than bypassing the restriction.

A session-local `AGENTS.md` explains the event commands, evidence rules, and treatment of filenames and artifact contents as untrusted data.

## Agent workflow

The agent can inspect the current selection and tree:

```bash
guiai state --session .
guiai tree --session .
```

After obtaining actual evidence, it records a discovery with a stable ID and parent:

```bash
guiai emit --session . \
  --id function:0x50c8 \
  --parent artifact:ARTIFACT_SHA256 \
  --type function \
  --label 'main @ 0x50c8' \
  --status in_progress \
  --evidence analysis/main-functions.json \
  --note 'Recovered through Ablation CFG analysis'
```

Supported node types are `artifact`, `function`, `evidence`, `observation`, `hypothesis`, `finding`, and `note`.

For high-volume discovery, provide a JSON array of event objects and use one lock and disk sync per batch:

```bash
guiai emit-many --session . --file discoveries.json
```

Use `--file -` to read the array from stdin. Batch emission validates every event and rejects the entire batch if a parent is missing, an event is invalid, or a cycle would result. Replaying an identical batch is a no-op.

The user can then select that function and say “work more on this.” The agent reads `guiai state` and continues from the selected evidence instead of rediscovering it.

## Status meanings

- `not_started`: no recorded work in this session; it does not mean the artifact was never analyzed elsewhere.
- `in_progress`: active investigation is recorded.
- `partial`: some evidence exists, but questions remain.
- `blocked`: a specific platform, format, tool, or runtime limitation is recorded.
- `reviewed`: a human reviewed the node; this is not automatically confirmation of a hypothesis.
- `complete_scoped`: complete only for the explicit `--scope`, never blanket binary coverage.
- `rejected`: the node or hypothesis was rejected.
- `not_applicable`: documentation, metadata, or another non-RE target.

## Human and CLI commands

Print the current tree or selection:

```bash
guiai tree --session /path/to/investigation-session
guiai tree --session /path/to/investigation-session --json
guiai state --session /path/to/investigation-session
```

Record a human status update outside the GUI:

```bash
guiai review function:0x50c8 \
  --session /path/to/investigation-session \
  --status partial \
  --note 'Continue caller analysis'
```

## Session files

```text
investigation-session/
├── AGENTS.md          # Agent instructions and evidence rules
├── bin/guiai          # Executable agent-facing CLI wrapper
├── session.json       # Target kind, path, and appropriate identity
├── project.json       # Saved active Lab and Lab manifest
├── events.jsonl       # Lab #1 discovery history
├── state.json         # Lab #1 selected node
├── preferences.json   # Optional terminal and workspace preferences
└── investigations/
    └── 0002/          # Lab #2, with the same session-file structure
        ├── AGENTS.md
        ├── bin/guiai
        ├── session.json
        ├── events.jsonl
        └── state.json
```

The GUI writes selection state and the project manifest atomically. Event reads use shared locks, writes use exclusive locks, and initialization uses a separate lock. Parent IDs and event cycles are validated to prevent orphaned or unreachable branches. Corrupt session files produce a visible workspace or restoration error. Corrupt preferences are reported without silently replacing the file; applying Preferences is an explicit save. Empty filter results show guidance and can be cleared with **Reset filters**.

## Current boundaries

- The GUI does not run Ablation automatically; the interactive agent decides which tools to invoke.
- Agent observations and hypotheses remain distinct from tool evidence and human-confirmed findings.
- The first version is a session tree, not a universal module browser or full analysis-results editor.
- Terminal compatibility depends on the agent CLI. The integration is proven with Kimi and local interactive fixtures, not every coding-agent TUI.
- GUIAI is included in the Ablation repository and bundles its METRIX support modules. Native GTK validation covers Linux with X11; other platforms and terminal agents require their own validation.
- Nested X11 validation does not certify the host Wayland compositor, graphics driver, or hardware. See the full-system freeze investigation in [HARDENING.md](HARDENING.md) before repeating live-display stress tests.

## Validation and hardening

Run the repeatable core, native, and targeted desktop-input suites:

```bash
python3 stress/run_stress.py
python3 stress/native_stress.py
python3 stress/desktop_input_stress.py
python3 stress/gtk_stress.py
```

For repeated GUI testing, use the nested launcher instead of opening test windows on the live desktop. It starts a private Xephyr X11 display with software rendering, refuses to reuse an active display, and cleans up its own server:

```bash
PYTHON=/path/to/venv/bin/python stress/nested_x11.sh
```

To run one command in the same isolated environment, append it, for example `PYTHON=/path/to/venv/bin/python stress/nested_x11.sh python3 stress/gtk_stress.py --failfast`. The launcher requires Xephyr and `xwininfo`; it does not use a browser or change the production interface.

The desktop-input suite requires an X11 display (the live display or the nested launcher). It checks terminal focus, ordinary and shifted keys, editing keys, clipboard operations, directory selection and rescanning, the session CLI wrapper, Unicode handler-to-PTY delivery, and cleanup. Unicode is tested at the terminal handler boundary because Tk does not synthesize arbitrary input-method characters. The GTK suite additionally checks native disclosure, theme-colored icons through pixel assertions, real VTE discovery, background rescan success and cancellation, the actual `+` and Preferences controls, collapsed section visibility, legacy-layout migration, multiple independent live CLIs, restart restoration, custom palettes, the canonical workspace and divider, and the normal `Application.run()` lifecycle in a fresh process. **Run the multi-tab VTE lifecycle test on the normal desktop**: a window-manager-free Xephyr display is suitable for isolated widget tests but is not a valid substitute for that workflow.

The canonical workspace has one outer divider between Lab and the terminal. **Chart** reveals a nested divider with the Lab tree beside **Rings** or **Treemap**; the tree is never replaced by a chart. Column headers are not draggable: Lab flexes and middle-ellipsizes long labels, Type appears only for mixed-type matching rows, and Status retains a bounded width. Type and Status become compact only while a chart is visible and restore when it is hidden. Breadcrumbs and chart selection update the real session selection. Node actions remain visible below the workspace and compact to icons at narrow widths without wrapping; **Node details** independently reveals actual metadata labels without rebuilding the charts. Footer status counts apply filters, and routine status changes expose append-only Undo. Ring sectors select real nodes, the center moves to the parent, arrow keys navigate the hierarchy, and the mouse wheel changes the visible depth. Small or deeper nodes are counted explicitly rather than silently treated as covered.

The current suite contains 29 core tests, 21 native tests, 31 GTK/map/rings integration tests, and one complete desktop workflow: 82 checks in total. Coverage includes concurrent file and directory initialization, real directory scale, malformed metadata and events, cycles, legacy file sessions, deep trees, independent investigation histories, readable status/type labels, adaptive Type visibility, long-name presentation, streamlined actions, clickable status summaries, exact append-only Undo, preference persistence and corruption, four visual workspace layouts, active-Lab project restoration, collapsed Lab/Workspace-layout/Terminal/ANSI-palette sections with mapped content, legacy-layout migration, canonical pane positions, stars that survive selection and reopen, row-level star interaction, eye-icon disclosure, mapped and height-bounded detail labels, permanent tree/chart layout, compact/restored columns, single-process tab churn with memory and object-retention checks, duplicate starts, failed spawns, deferred-start cancellation, tab-label teardown, treemap area/descendant counts, Baobab palette independence from status, pagination, exact container allocation and tile reuse, ring geometry and real Cairo rendering, angular and depth limits, keyboard navigation, shared chart selection, terminal input readiness, partial terminal writes, stubborn processes, and repeated shutdown. See [HARDENING.md](HARDENING.md) for the defect ledger, installed-artifact evidence, and remaining limits.
