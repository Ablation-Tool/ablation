# Review & Evidence Integrity

## Purpose

The review workflow records what has been inspected, what remains unresolved, and what a human has actually reviewed. It separates agent output from human judgment instead of turning every discovered node into a confirmed vulnerability.

Each state change is an event in the investigation history, not an in-place rewrite of the past.

## Status meanings

| Status | Meaning |
|---|---|
| `not_started` | No work has been recorded in this session; it does not prove the item was never analyzed elsewhere. |
| `in_progress` | Active investigation is recorded. |
| `partial` | Some evidence exists, but questions or branches remain. |
| `blocked` | A specific tool, platform, format, or runtime limitation is recorded. |
| `reviewed` | A human reviewed the node; it is not automatic confirmation of a hypothesis. |
| `complete_scoped` | Complete only within an explicit scope, never blanket binary coverage. |
| `rejected` | The node or hypothesis was rejected. |
| `not_applicable` | The item is documentation, metadata, or otherwise outside the RE target. |

A parent's own status is not inferred from its children. A parent with reviewed children can still have unexamined branches of its own.

## Human actions

**Flag for follow-up** marks a node partial and records that the human requested more work. Repeating that request does not duplicate the marker. **Mark as reviewed** records the human's review without claiming that the underlying hypothesis is proven.

**Open in CLI** focuses the agent on the selected node. A follow-up prompt includes its ID, label, and evidence path, with instructions to build on existing evidence and treat artifact content as untrusted data.

**Undo** appends a restoration event. It does not delete or rewrite history, so the sequence of review decisions remains auditable. Row-level stars are bookmarks, not review states, and persist separately in `state.json`.

## Filtering and navigation

The user can filter by status or text while preserving ancestor context. Footer counts expose the complete status breakdown and apply the selected filter when clicked. This makes it practical to find untouched branches, blocked evidence, partial hypotheses, or reviewed results without memorizing the session.

Human-readable labels preserve the raw CLI status value in the underlying event. A chart's color is not a substitute for these explicit states.

## Example CLI review

```bash
gem review function:0x50c8 \
  --session /path/to/project \
  --status partial \
  --note 'Continue caller analysis and verify the length source'
```

The command emits a new event from the human. An agent can also emit observations, hypotheses, or findings from its own source, but the human must still decide whether the evidence supports the conclusion.

## Evidence and scope

A scoped-complete event requires a nonempty scope. That scope should identify exactly what was inspected, such as one function's direct callers or a named firmware partition. It must not be used to imply that an entire binary, firmware image, or directory is complete.

Observations and hypotheses remain distinct from tool evidence and human-confirmed findings. A filename, agent assertion, or large subtree is not proof of coverage or impact.

## Implementation map

- `gem-lab/gem/events.py`: status validation, event history, selection, and scoped completion
- `gem-lab/gem/cli.py`: `review`, `state`, `tree`, and event emission
- `gem-lab/gem/app.py`: Tk review actions, follow-up prompts, and status summaries
- `gem-lab/gem/gtk_app.py`: GTK status updates, bookmarks, and append-only undo

## Validation

Tests cover idempotent follow-up requests, exact append-only undo, persistent bookmarks, human-readable status labels, status filters, scoped completion validation, corrupt state handling, and independent histories. The workflow deliberately preserves rejected, blocked, and not-applicable states rather than merging them into a simple complete/incomplete model.
