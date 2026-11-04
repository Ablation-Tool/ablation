# Token Allocation

## Purpose

**Token Allocation** is a working strategy for spending an AI Agent's limited context on the current investigation instead of repeatedly rediscovering it. GEM's visual workspace provides external memory: the human and agent can inspect a selected node, its evidence, and its status rather than replaying an entire session.

This is not an automatic token counter, a compression promise, or a license to discard evidence. The goal is to reduce unnecessary context while preserving analysis quality, evidence quantity, and investigation coverage.

## Navigation before generation

A useful token-allocation sequence is:

1. Read `gem state` to identify the selected investigation node.
2. Read `gem tree` to see which branches have recorded work and which remain untouched.
3. Select only the evidence needed for the current question.
4. Perform actual analysis and record the result with a stable ID and parent.
5. Resume from the updated state rather than re-reading the whole conversation or corpus.

The Lab's filters, breadcrumbs, status counts, and node details let the human narrow the next request. A targeted prompt such as “continue from this selected function and its callers” allocates fewer tokens to navigation and more to reasoning and validation.

## Scoped retrieval without losing quantity

Full tool output and supporting artifacts should remain on disk or in their original evidence location. The session stores an **evidence path** and a concise result, not a requirement to place every byte into the model context at once. The agent can retrieve a larger artifact or output slice when that evidence becomes necessary.

METRIX queries provide a similar corpus-level retrieval model:

```bash
metrix scan /path/to/material --output /path/to/metrix-output
metrix query --output /path/to/metrix-output --architecture arm64 --contains parser --limit 20
metrix show ARTIFACT_ID --output /path/to/metrix-output
```

Filtering by architecture, class, status, analysis status, and text reduces irrelevant retrieval. `query` defaults to a bounded result count; `--limit 0` preserves the explicit unlimited option when complete output is required. Token allocation must not silently turn into omitted evidence or reduced RE scope.

## Incremental work preserves quality

Stable node IDs and parent/child relationships let the agent extend a branch instead of recreating it. Status values distinguish untouched, in-progress, partial, blocked, reviewed, scoped-complete, rejected, and not-applicable work. The workspace can therefore show what remains without claiming that an abbreviated context means complete analysis.

Use `gem emit` for a discovery and `gem emit-many` for a validated batch. Batch emission reduces repeated locking and disk synchronization overhead, but its purpose is not to compress an investigation into fewer facts. Each result still needs supporting evidence and explicit uncertainty.

When context compaction or an agent restart occurs, the next agent should inspect the recorded selection and history rather than rely on memory of the old chat. This protects continuity without preserving an inflated transcript.

## Performance without loss

Token allocation can improve performance by:

- Avoiding repeated directory scans and rediscovery of existing branches.
- Using selected-node state instead of the full event log for the next action.
- Retrieving evidence only when it is needed for a decision.
- Preserving large outputs outside the prompt while retaining their paths for later verification.
- Using workspace summaries and charts for navigation instead of repeatedly asking the agent to reconstruct session structure.

These gains come from **less redundant work**, not from lower-quality analysis or fewer recorded facts. Rings and Treemap show subtree node count, not token count or analysis coverage.

## Limits

Token allocation cannot guarantee a specific reduction in model usage or cost. Context limits, agent implementations, tool output size, and provider policies vary. It also cannot make an untested observation trustworthy or convert a scoped result into blanket coverage.

A concise prompt must still identify the target and the actual evidence needed. If a task requires the complete artifact, log, or directory, use it rather than truncating for the sake of token savings. Preserving quality and quantity takes precedence over fitting an arbitrary context budget.

## Implementation map

- `gem-lab/gem/events.py`: stable event history, selection, and incremental discovery state
- `gem-lab/gem/cli.py`: targeted `state`, `tree`, `emit`, and `emit-many` operations
- `gem-lab/gem/app.py` and `gem-lab/gem/gtk_app.py`: visual selection, filtering, details, and status navigation
- `gem-lab/metrix/cli.py`: scoped corpus queries, bounded or explicitly unlimited output, and evidence retrieval
- `gem-lab/metrix/desktop.py`: interactive terminal without a separate model-context store

For the role model behind this external memory, see [Unified Memory Architecture](unified-memory-architecture.md).
