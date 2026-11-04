# GEM Lab

GEM (Graphics Environment Manager) is Ablation's **standard native graphical environment** for agent-guided reverse-engineering sessions. The visible application name is **GEM**; the `gem` package, CLI, `GEM_*` environment variables, and session protocol are the only current interface. The distribution also includes the METRIX support package, so no separate METRIX checkout is required.

The user’s real interactive CLI supplies labor. The workspace supplies memory and navigation. The human supplies direction and judgment. GEM supports any interactive agent executable through `--agent`, and custom argument lists through `--agent-command`; it provides no model or credentials.

For how this improves investigation throughput without making analysis computation faster, see [GEM performance and investigation memory](../docs/reference-modules/gem-performance.md).

## Ablation + GEM (Graphics Environment Manager)

Ablation + GEM (Graphics Environment Manager) is one product and one default download. Ablation supplies the required CLI and analysis framework; GEM (Graphics Environment Manager) supplies the native UI and graphical execution environment. The full Lab workflow depends on Ablation, while Ablation can operate independently with the **CLI Only** installation.

The human selects an artifact. The agent reads `gem state`, calls `gem begin` with the exact selection revision, performs real analysis through Ablation, and records results with `gem emit` or `gem emit-many`. This machine-readable protocol replaces screenshot inference, and stale selections are rejected. The [GEM guide](GEM.md) contains the Mermaid architecture flowchart and distinguishes authoritative investigation state from derived visual state.

## What the workbench does

- Embeds the actual interactive agent CLI in a native VTE terminal beside each investigation tree, with guarded startup, duplicate prevention, and explicit failure handling.
- Accepts a single binary or a material directory, with real top-level directory inventory.
- Shows an agent-grown investigation tree with **Lab** and **Status** columns, clickable breadcrumbs, and Up/Home navigation. **Type** appears only when matching rows have different types. Human-readable status and type labels preserve the raw CLI values. Long Lab names use middle ellipsizing with full-name/path tooltips.
- Offers optional **Rings**, **Treemap**, and **GEM** visualizations beside the authoritative tree. Treemap area and ring angle both represent subtree node count, not bytes or analysis coverage. Both use Ubuntu Baobab's position/depth palette; status remains explicit text rather than being encoded by tile color. Treemap retains pagination, and Rings adapts Baobab's concentric-sector geometry. All three share selection, breadcrumbs, and `state.json` with the CLI. Rings supports click-to-inspect, center-to-go-up, tooltips, keyboard navigation, and scroll-controlled depth, and reports nodes omitted by angular or depth limits. GEM converts bounded visible nodes and parent/child relationships into Spatial IR, numerically checks geometry, renders native Cairo/SVG and real VDI output, and replays exported artifacts before recording scoped evidence. See [GEM](GEM.md).
- Tracks not-started, in-progress, partial, blocked, reviewed, scoped-complete, rejected, and not-applicable work without merging distinct states or deriving a parent's own status from its children.
- Filters the tree by status, bookmarks, or text while retaining ancestor context. **Starred** shows bookmarked nodes without changing their review status. Clickable footer status counts apply the corresponding status filter, and the complete breakdown remains available below the workspace.
- Shares each investigation's selected node with its corresponding CLI through its own `state.json`. Startup instructions require the agent to read the current selection before investigation requests and record evidence-backed status changes through the GEM CLI. Row-level stars are bookmarks, not review states; they persist in the same state file and can be changed from the tree or the selected-node action.
- Creates paired **Lab N** tabs with the native `+` button. Every tab has an independent session, event history, selection, stars, and real CLI.
- Restores saved investigation tabs and the active Lab on startup. **Save project** records the project manifest and preferences; discovery history and selections are saved continuously. Restored CLIs start when their tab is selected; closing a tab stops its CLI but retains its history and releases the tab label, workspace, and pending callbacks.
- Keeps one configurable workspace with an optional chart beside the Lab tree. The Lab and terminal can be side by side or stacked in either order. The outer and chart dividers remain adjustable. Node actions remain visible and compact to icons at narrow widths without wrapping. **Node details** uses a collapsed-by-default bowtie toggle with normal and inverse icon states and a height-bounded native disclosure, so expanded metadata cannot push actions or the status summary off-screen.
- Uses Ubuntu's native GTK notebook, tree, disclosure, action, and VTE terminal model when available, with official Vanilla Framework icons. The Tk interface remains a single-investigation fallback on Linux and the native interface on Windows and macOS.
- Uses the configured Ubuntu interface and system monospace fonts with native theme text colors in light and dark modes. Tree statuses remain explicit text rather than depending on hard-coded gray or status colors.
- Uses theme-derived alternating row shading and theme-colored icons while preserving native selection colors.
- Offers native terminal schemes, editable foreground/background and all 16 ANSI palette colors, and a terminal font selector through **Preferences**. Four numbered visual previews select the Lab/terminal arrangement without text-heavy options. Lab, Workspace layout, Terminal, and ANSI palette use independent collapsed disclosure sections in GTK; Tk presents a compact graphical layout dialog. Preferences apply to all open Labs and persist in the root session.
- Provides scrollbars, directory rescanning, and a selection-specific follow-up prompt.
- Accepts local files and folders dragged into the embedded CLI on Linux, Windows, and macOS. Drops insert shell-quoted paths and a trailing space without Enter, so the user reviews the command before running it. Missing paths, control characters, non-local URIs, unavailable CLIs, and batches over 8 MiB are rejected explicitly.
- Uses the woven-diamond logo as a titlebar settings toggle with **a11y Optimization**, **OS Optimization**, and **Debug**. Each runs a read-only audit and shows findings before **Allow Permission** sends one bounded request to an active AI agent. **Deny Permission** performs no terminal action. OS Optimization checks Python/OS support, Tkinter, terminal and drag-and-drop dependencies, Linux GTK/VTE, data-directory writability, and the configured agent. Debug uses the same evidence for scoped troubleshooting.
- Offers **Accessible Volume** in Settings. The optional local DistilGPT2 provider measures the current selection and recent evidence, writes the raw probabilities and report, and selects a separate `tool` evidence event. `gem measure --session SESSION` provides the same workflow; repeated `--candidate` options compare concentration deltas for proposed actions without authorizing or executing them. Interactive agents are not measured, and concentration is not correctness, safety, or action authorization.
- Provides built-in accessibility preferences with persistent system, colorblind-safe, and high-contrast palettes. Text contrast is measured against the active background with a 4.5:1 target. PASS and REVIEW labels, bold subjects, and section headings preserve meaning independently of color. Descriptive control labels, screen-reader descriptions, status roles, the text-based Lab tree alternative, and keyboard shortcuts are built in: Alt+S opens Settings, Alt+O opens OS Optimization, Alt+A opens a11y Optimization, and Escape closes the panels. Automated checks do not replace manual validation with the user's assistive technology.
- Offers **Show in file manager** to reveal selected evidence in Nautilus, Finder, or Windows Explorer after an explicit user action; it does not execute artifacts.
- Keeps **Open in CLI** as the primary node action, with **Flag for follow-up**, **Mark as reviewed**, and an overflow menu for copy/file-manager actions. Status feedback offers Undo, which appends a restoration event rather than deleting or rewriting history.
- Preserves append-only discovery histories in each investigation's `events.jsonl`.
- Uses the Ablation CLI and analysis framework through the shared Lab protocol, without requiring a second framework.

There is no browser, fake built-in AI, separate chatbot protocol, or automatic blanket vulnerability verdict.

## Architecture

```text
Lab N                           Native Ablation workbench (Tk fallback)
      │                                  │
      ├─ gem emit ───────────────► events.jsonl
      │                                  │
      └─ gem state ◄─────────────── state.json
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
python -m pip install ./gem-lab
```

METRIX, `pyte`, and the pinned `tkinterdnd2` drag-and-drop bridge are included or installed automatically. The Installation Prompt installs the standard Ablation CLI and GEM together. The source command above installs GEM only; add the full CLI with `python -m pip install -e .` when needed. No separate METRIX checkout is required.

Start with the **[all-platform installation guide](INSTALL.md)** or copy the **[Universal OS Installation Prompt](INSTALL-PROMPT.md)** into your agent.

## Start a session

Open the installed Desktop icon, or run `gem launch`, to choose a binary or material directory in a native dialog. Each target gets a stable session under the user's GEM data directory. The embedded agent starts in the `gem-lab` root: the repository's `gem-lab` directory for source checkouts, or `~/gem-lab` for packaged installations. The launcher supplies the GEM session, state, event, target, and CLI environment there so the agent can interact with the Lab. The launcher detects an installed `kimi`, `claude`, or `codex` agent, including common user executable directories omitted from graphical-session `PATH` values, and embeds the first available agent. An explicit `--agent` or `--agent-command` takes precedence; use `--no-agent` to open only the investigation tree. If no supported agent is installed, the Lab still opens and reports that no external CLI is configured rather than substituting another program. Linux selects the native GTK interface by default when GTK/VTE is available. Native Windows and macOS use Tk; command-line users on those platforms can run `gem launch --toolkit tk`. The installer does not install an AI agent, model, or credentials.

Investigate one binary with an embedded agent:

```bash
gem lab /path/to/binary \
  --session /path/to/investigation-session \
  --agent kimi
```

Or investigate a material directory with any installed interactive agent:

```bash
gem lab /path/to/material-directory \
  --session /path/to/investigation-session \
  --agent AGENT_EXECUTABLE
```

`AGENT_EXECUTABLE` can be `kimi`, `claude`, `codex`, or another executable. For an agent that needs custom arguments:

```bash
gem lab /path/to/material-directory \
  --session /path/to/investigation-session \
  --agent-command 'your-interactive-agent-cli --flag'
```

Agent CLIs are installed and configured separately. Their authentication, permissions, trust prompts, provider data policy, and terminal behavior remain their own. GEM does not supply a model, API key, or second chatbot. Kimi and local interactive fixtures are validated; other agents may require compatibility testing for their specific terminal interface.

By default, `desktop` selects the native GTK interface when GTK and VTE are available. Use `--toolkit gtk` to require it or `--toolkit tk` to select the Tk fallback explicitly.

The macOS offline installer also creates **GEM.app**. It opens the same GEM home screen with **Open binary** and **Open directory** actions, then creates a stable per-target session and opens the Tk workbench with an installed agent when available. The bundle includes its Python environment and icon and can be moved on the same Mac. `Contents/MacOS/GEM` accepts the same command-line arguments as `gem`; `Contents/MacOS/GEM --self-test` verifies the bundled runtime. The locally created app is not signed or Apple-notarized.

Directory initialization adds the root and its real top-level entries. It does not recurse, hash directory contents, or claim analysis coverage. **Rescan directory** repeats the idempotent top-level inventory; deeper work is recorded by the agent after inspection. A directory's identity is based on its absolute path, not a content digest. Single files retain their full SHA256 identity.

The session must be outside a directory target. A session belongs to one target; reusing it for a different target is rejected. Existing file sessions remain compatible.

In the GTK interface, **Lab 1** uses the root session. The `+` button opens a native folder chooser before creating `investigations/0002`, `investigations/0003`, and so on. The selected folder becomes that tab's terminal working directory and is saved independently in its `session.json`; it does not change the RE target. Each tab has its own agent instructions, wrapper, event log, selection, and terminal directory. Cancelling or rejecting an invalid directory creates no tab. Saved numbered investigations and their directories are restored on startup. If a saved directory no longer exists, that terminal uses its session directory and the window shows a warning. Closing a tab stops its terminal without deleting history, so that investigation is restored on the next launch. The command-line `--workspace` option, when present, overrides saved per-tab directories.

**Save project** writes `project.json` with the active Lab, Lab session locations, terminal directories, and selected nodes, and saves the current preferences. Closing the application saves the project automatically. Reopen it with `gem lab TARGET --session SESSION` as usual; the authoritative event logs, selections, and bookmarks were already persisted and are not duplicated into a second database. The live process, terminal scrollback, and AI Agent conversation context are not serialized as project memory. The Lab's recorded discoveries and current selection are the supported continuation state.

The native **Preferences** dialog offers Ubuntu/system, Tango, Linux console, XTerm, Solarized dark/light, high-contrast, and custom terminal colors. Custom editing covers foreground, background, and all 16 ANSI palette entries. The terminal defaults to the configured system monospace font; any font installed by the user can be selected through the native font button. Lab, Workspace layout, Terminal, and ANSI palette are collapsed by default in GTK so users reveal only the controls they need. Four graphical choices place the Lab left, right, above, or below the AI Agent; **1** is the Lab and **2** is the AI Agent. GTK applies the selection with **Apply**, while Tk saves it immediately. Every open Lab keeps its original tree, chart, and terminal widgets. One root preference set applies to all open investigations and is restored on the next launch.

With `desktop`, omit `--agent` and `--agent-command` or pass `--no-agent` to use only the investigation tree; `launch` auto-detects an agent unless `--no-agent` is present. Both commands start the agent in the `gem-lab` root by default; `--workspace` overrides it. New Labs always ask for a directory. The embedded CLI receives:

- `GEM_SESSION` — session directory containing authoritative state
- `GEM_WORKSPACE` — this terminal's actual working directory, independent of the session and RE target
- `GEM_STATE` — selected-node state file
- `GEM_EVENTS` — append-only event log
- `GEM_CLI` — executable session-local `bin/gem` wrapper
- `GEM_TARGET` — file or directory being investigated
- `GEM_TARGET_KIND` — `file` or `directory`
- `GEM_ROOT_ID` — root node ID for new discoveries
- `ABLATION_BINARY` — current binary only for a single-file target
- `ABLATION_CLI` — Ablation command, defaulting to `ablation`

The wrapper directory and current Python executable directory are added to the agent's `PATH`, so both `"$GEM_CLI"` and `gem` work as shell commands. The wrapper invokes the current Python interpreter and preserves all arguments; it is not a multiword command string. The agent's command runner must be able to access that interpreter and installed packages. If it uses a sandbox or restricted filesystem, choose an accessible installation location rather than bypassing the restriction.

A session-local `AGENTS.md` explains the event commands, evidence rules, and treatment of filenames and artifact contents as untrusted data. Startup integration loads the same shared-Lab protocol explicitly: Kimi receives a session-owned agent profile, Claude receives an appended system prompt, and custom CLIs receive an initial terminal instruction. Existing resume or custom-prompt options are preserved and use the terminal fallback rather than being overridden.

## Agent workflow

The agent can inspect the current selection and tree:

```bash
gem state --session .
gem tree --session .
```

Before beginning selected work, the agent uses the exact `selected_id` and `revision` returned by `state`:

```bash
gem begin --session . \
  --expected-id function:0x50c8 \
  --expected-revision 3
```

The compare-and-commit operation preserves the selected event's fields and records `in_progress` only if the selection and revision remain current. A stale result must be read again, not bypassed with a direct status emit. Selection, bookmark, and begin operations advance the revision.

After obtaining actual evidence, it records a discovery with a stable ID and parent:

```bash
gem emit --session . \
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
gem emit-many --session . --file discoveries.json
```

Use `--file -` to read the array from stdin. Batch emission validates every event and rejects the entire batch if a parent is missing, an event is invalid, or a cycle would result. Replaying an identical batch is a no-op.

The user can then select that function and say “work more on this.” The agent reads `gem state` and continues from the selected evidence instead of rediscovering it.

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
gem tree --session /path/to/investigation-session
gem tree --session /path/to/investigation-session --json
gem state --session /path/to/investigation-session
```

Record a human status update outside the GUI:

```bash
gem review function:0x50c8 \
  --session /path/to/investigation-session \
  --status partial \
  --note 'Continue caller analysis'
```

## Session files

```text
investigation-session/
├── AGENTS.md          # Agent instructions and evidence rules
├── bin/gem          # Executable agent-facing CLI wrapper
├── session.json       # Target kind, path, and appropriate identity
├── project.json       # Saved active Lab and Lab manifest
├── events.jsonl       # Lab 1 discovery history
├── state.json         # Lab 1 selected node
├── preferences.json   # Optional terminal and workspace preferences
└── investigations/
    └── 0002/          # Lab 2, with the same session-file structure
        ├── AGENTS.md
        ├── bin/gem
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
- GEM is included in the Ablation repository and bundles its METRIX support modules. Native GTK validation covers Linux with X11; other platforms and terminal agents require their own validation.
- Nested X11 validation does not certify the host Wayland compositor, graphics driver, or hardware. See the full-system freeze investigation in [HARDENING.md](HARDENING.md) before repeating live-display stress tests.

## Validation and hardening

Run the repeatable core, native, and targeted desktop-input suites:

```bash
python3 stress/run_stress.py
python3 stress/native_stress.py
python3 stress/desktop_input_stress.py
python3 stress/gtk_stress.py
python3 stress/gem_stress.py
python3 stress/installer_stress.py
```

For repeated GUI testing, use the nested launcher instead of opening test windows on the live desktop. It starts a private Xephyr X11 display with software rendering, refuses to reuse an active display, and cleans up its own server:

```bash
PYTHON=/path/to/venv/bin/python stress/nested_x11.sh
```

To run one command in the same isolated environment, append it, for example `PYTHON=/path/to/venv/bin/python stress/nested_x11.sh python3 stress/gtk_stress.py --failfast`. The launcher requires Xephyr and `xwininfo`; it does not use a browser or change the production interface.

The desktop-input suite requires an X11 display (the live display or the nested launcher). It checks terminal focus, ordinary and shifted keys, editing keys, clipboard operations, directory selection and rescanning, the session CLI wrapper, Unicode handler-to-PTY delivery, and cleanup. Unicode is tested at the terminal handler boundary because Tk does not synthesize arbitrary input-method characters. The GTK suite additionally checks native disclosure, theme-colored icons through pixel assertions, real VTE discovery, background rescan success and cancellation, the actual `+` and Preferences controls, collapsed section visibility, legacy-layout migration, multiple independent live CLIs, restart restoration, custom palettes, the canonical workspace and divider, and the normal `Application.run()` lifecycle in a fresh process. **Run the multi-tab VTE lifecycle test on the normal desktop**: a window-manager-free Xephyr display is suitable for isolated widget tests but is not a valid substitute for that workflow.

The canonical workspace has one outer divider between Lab and the terminal. **Chart** reveals a nested divider with the Lab tree beside **Rings**, **Treemap**, or **GEM**; the tree is never replaced by a chart. Column headers are not draggable: Lab flexes and middle-ellipsizes long labels, Type appears only for mixed-type matching rows, and Status retains a bounded width. Type and Status become compact only while a chart is visible and restore when it is hidden. Breadcrumbs and chart selection update the real session selection. Node actions remain visible below the workspace and compact to icons at narrow widths without wrapping; **Node details** independently reveals actual metadata labels without rebuilding the charts. Footer status counts apply filters, and routine status changes expose append-only Undo. Ring sectors select real nodes, the center moves to the parent, arrow keys navigate the hierarchy, and the mouse wheel changes the visible depth. Small or deeper nodes are counted explicitly rather than silently treated as covered.

The current suite contains 55 core tests, 26 native tests, 34 GTK/map/rings/GEM integration tests, 32 GEM environment/engine/native tests, one complete desktop workflow, and 12 universal-installer tests: 160 checks in total. Native Windows and macOS packages additionally run their platform-specific drag-and-drop, inline safety and accessibility audits, icon, terminal, and cleanup checks. Coverage includes concurrent file and directory initialization, real directory scale, malformed metadata and events, cycles, legacy file sessions, deep trees, independent investigation histories, readable status/type labels, adaptive Type visibility, long-name presentation, streamlined actions, clickable status summaries, exact append-only Undo, preference persistence and corruption, four visual workspace layouts, active-Lab project restoration, collapsed Lab/Workspace-layout/Terminal/ANSI-palette sections with mapped content, legacy-layout migration, canonical pane positions, stars that survive selection and reopen, row-level star interaction, eye-icon disclosure, mapped and height-bounded detail labels, permanent tree/chart layout, compact/restored columns, single-process tab churn with memory and object-retention checks, duplicate starts, failed spawns, deferred-start cancellation, tab-label teardown, treemap area/descendant counts, Baobab palette independence from status, pagination, exact container allocation and tile reuse, ring geometry and real Cairo rendering, angular and depth limits, keyboard navigation, shared chart selection, terminal input readiness, partial terminal writes, stubborn processes, and repeated shutdown. See [HARDENING.md](HARDENING.md) for the defect ledger, installed-artifact evidence, and remaining limits.
