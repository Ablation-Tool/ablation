# Layout Preferences

## Purpose

Layout preferences let the user arrange the Lab and the embedded AI Agent without changing the investigation's content. Four visual choices support different screens, reading habits, and working styles while preserving the same tree, chart, terminal, selection, and session history.

## Available arrangements

| Preference | Lab | AI Agent |
|---|---|---|
| `lab-left` | Left | Right |
| `lab-right` | Right | Left |
| `lab-top` | Above | Below |
| `lab-bottom` | Below | Above |

The preview diagrams use **1** for the Lab and **2** for the AI Agent. They show the arrangement graphically instead of requiring the user to interpret layout names.

GTK presents native radio-button previews in the collapsible **Workspace layout** section and applies them with **Apply**. Tk presents a compact graphical dialog and saves a selection immediately.

## Real pane changes

Changing the preference changes the actual pane orientation and child order, not just a preview image. GTK re-packs the existing left workspace and VTE terminal. Tk rebuilds only the split container because its orientation is read-only after creation; the tree and terminal objects retain their original parent and state.

The outer divider remains adjustable. When the arrangement changes, GEM preserves its proportion where possible and keeps both panes visible at small sizes. Nested chart panes, node details, selections, and terminal processes are not recreated as a side effect.

Every open GTK Lab receives the same root layout preference. Tk applies it to its single investigation. No alternate workspace model or hidden second tree is created.

## Persistence and migration

The layout is stored in the root `preferences.json`. The shared layout helper validates values, accepts the older `horizontal` and `vertical` names as `lab-left` and `lab-top`, and writes changes atomically. It preserves unrelated terminal color and font settings when Tk changes only the layout.

Missing preferences default to `lab-left`. Invalid layouts, non-string values, oversized files, and malformed JSON produce visible errors instead of silently replacing the user's preferences. The file has a 64 KiB limit.

## Typical use

- Choose `lab-left` for a conventional tree-plus-terminal workflow.
- Choose `lab-right` when the terminal should lead the visual workflow.
- Choose `lab-top` to give the Lab full width for long names and evidence.
- Choose `lab-bottom` to give the interactive CLI full width while keeping the Lab below it.

The choice affects presentation only. It does not change which agent runs, which directory is being analyzed, or which evidence has been recorded.

## Implementation map

- `gem-lab/gem/layout.py`: layout names, migration, validation, and atomic persistence
- `gem-lab/gem/preferences.py`: combined terminal and workspace preferences for GTK
- `gem-lab/gem/gtk_app.py`: preview drawing, radio controls, and real GTK pane arrangement
- `gem-lab/gem/app.py`: Tk preview controls, pane-container rebuilding, and deferred divider restoration

## Validation

Tests exercise all four arrangements, preview controls, actual child order, preserved tree/chart/terminal objects, mapped non-zero pane sizes, preference migration, corruption handling, and restoration after reopening. Native Windows and macOS tests also cover layout selection and project saving.
