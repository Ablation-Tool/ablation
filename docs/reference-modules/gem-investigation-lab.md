# Lab & Navigation

## Purpose

The **Investigation Lab** is the navigable record of an agent-guided reverse-engineering session. It organizes artifacts, functions, evidence, observations, hypotheses, findings, and notes into a tree rather than forcing the user to reconstruct the investigation from a long terminal conversation.

The Lab is a view of authoritative session events, not a claim that every item has been analyzed or confirmed.

## Node model

Each event has an ID, optional parent, type, label, status, source, evidence path, note, and optional scope. Node types are:

- `artifact`: a binary, directory, firmware image, or other material.
- `function`: a recovered function or code region.
- `evidence`: supporting data or output.
- `observation`: an inspected fact or note.
- `hypothesis`: an untested or tentative explanation.
- `finding`: a result that still requires the appropriate confirmation.
- `note`: documentation, metadata, or a non-RE item.

IDs are stable, bounded, non-whitespace identifiers. Parent IDs must exist, and cycles are rejected. A parent's own status is not inferred from its children.

## Event history

The session's `events.jsonl` file is append-only. A new event for an existing ID supersedes the older state without erasing the earlier record. Replaying an identical event is a no-op, which makes repeated directory inventory and idempotent agent workflows safe.

Reads use shared locks; writes use exclusive locks. Initialization uses a separate lock. Invalid records, missing parents, malformed timestamps, and cyclic relationships produce explicit errors rather than silent tree corruption.

Use the GEM CLI to record discoveries instead of editing JSONL manually:

```bash
gem emit --session . \
  --id function:0x50c8 --parent artifact:ARTIFACT_SHA256 \
  --type function --label 'main @ 0x50c8' --status in_progress \
  --evidence analysis/main.json \
  --note 'Recovered through CFG analysis'
```

For a batch, use `gem emit-many --session . --file discoveries.json`, or pass the JSON array through stdin with `--file -`. Batch validation is atomic.

## Navigation and filtering

The Lab supports:

- Expandable parent/child relationships with stable expansion state.
- **Up**, **Home**, and clickable breadcrumbs.
- Case-insensitive text search across event data.
- Status filters that retain ancestors needed to understand a match.
- A selected-node details disclosure with type, source, status, evidence, scope, and notes.
- Breadcrumb-linked chart roots and selection shared with `state.json`.

An empty filter result displays guidance and a reset action rather than looking like missing evidence. Status counts in the footer apply the corresponding filter, so the user can navigate large investigations without memorizing every status category.

Long labels use middle ellipsizing and tooltips. Type appears only when matching rows have different types; Lab and Status remain the primary navigation columns.

## Charts and visual context

**Rings** and **Treemap** are alternative views of the same event graph, not replacements for the authoritative tree. Their area and angle represent subtree node count, not bytes, disk usage, vulnerability severity, or analysis coverage. Status remains explicit text.

The tree, charts, details, and CLI selection share one selected node. Chart pagination and depth/angular limits report omitted nodes explicitly rather than silently treating them as covered.

## Typical human workflow

1. Start with the root artifact or a top-level directory entry.
2. Ask the agent to inspect it and record actual output.
3. Expand the resulting function, observation, or evidence nodes.
4. Select a node to inspect details or request follow-up work.
5. Mark reviewed only after human review; use an explicit scope for scoped completion.

The selected node is available to the CLI through `state.json`. This is what lets a human direct labor without becoming the session database.

## Implementation map

- `gem-lab/gem/events.py`: event validation, initialization, history, selection, and counts
- `gem-lab/gem/app.py`: Tk tree, details, filtering, and selection actions
- `gem-lab/gem/gtk_app.py`: GTK tree, Lab tabs, native details, breadcrumbs, and chart coordination
- `gem-lab/gem/map_view.py`: Treemap layout and pagination
- `gem-lab/gem/rings_view.py`: concentric-sector geometry and navigation
- `gem-lab/gem/cli.py`: `tree`, `state`, `emit`, `emit-many`, and `review`

## Limits and validation

The initial directory inventory is top-level only. A filename or label is not evidence of analysis coverage, and an agent's hypothesis is not automatically a confirmed vulnerability.

Validation covers deep trees, thousands of siblings, Unicode nodes, corrupt event logs and selections, missing parents, cycles, concurrent writers, idempotent replay, expansion preservation, empty filters, and real chart selection. See `gem-lab/stress/run_stress.py`, `native_stress.py`, and `gtk_stress.py`.
