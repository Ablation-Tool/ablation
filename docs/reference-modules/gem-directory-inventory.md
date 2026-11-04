# Directory Inventory

## Purpose

Directory inventory turns a material directory into a small, honest starting point for an investigation. GEM records the real top-level entries and lets the agent and user decide what deserves deeper analysis. It does not claim that a directory tree has been recursively analyzed.

## Identity and session boundaries

A directory target has `target_kind=directory` and a directory ID based on the absolute path. This is an identity for the location, not a content digest or proof that the contents are unchanged.

A single-file target instead uses the file's full SHA256. A file and a directory cannot share a session as though they were the same target kind. Reusing a session for a different target is rejected.

The project/session directory must be outside the target directory. This keeps generated state, preferences, and event logs separate from the material being analyzed and prevents the inventory from treating its own session as RE material.

## Top-level entries

Initialization creates the root artifact and a child for each actual top-level entry, sorted with directories first and then case-insensitive names. Each child receives a stable path-based ID derived from its relative path, a parent ID, a type, an evidence path, and a note explaining that it has not been analyzed.

No function discovery, vulnerability conclusion, or recursive coverage is inferred from the entry's name, size, extension, or directory status.

Directory initialization uses an initialization lock and event batching. Reopening the same directory does not duplicate identical nodes. A rescan records newly observed entries through the same idempotent path model; historical events are not erased as a side effect.

## Rescanning and deeper work

**Rescan directory** repeats the top-level inventory. It is useful after the material directory changes, but it does not replace the agent's job of inspecting subdirectories and recording what was actually found.

Deeper work is represented explicitly by new evidence, functions, observations, hypotheses, findings, or notes. Every such event must name its parent and supporting evidence rather than being implied by a filesystem walk.

If a saved selection no longer exists, GEM falls back to the root artifact instead of keeping an invalid selected node. Corrupt metadata or event logs produce visible errors.

## Typical workflow

```bash
gem lab /path/to/material-directory \
  --session /path/to/project \
  --agent kimi
```

Then:

1. Review the root and real top-level entries in the Lab.
2. Select an entry that warrants inspection.
3. Ask the agent to examine it and record actual output.
4. Use `gem emit` or `gem emit-many` to record the supported discovery.
5. Use Rescan only when the top-level filesystem inventory itself needs refreshing.

The selected terminal directory can be changed independently when a different working directory is needed. That choice does not change the RE target or the session identity.

## Implementation map

- `gem-lab/gem/events.py`: target validation, directory identity, initialization, and idempotent event emission
- `gem-lab/gem/app.py`: Tk directory inventory and rescan action
- `gem-lab/gem/gtk_app.py`: GTK inventory, asynchronous rescan, cancellation, and restoration
- `gem-lab/gem/cli.py`: target/session command handling and state queries

## Limits and validation

Top-level inventory is not recursive analysis, a directory content hash, or evidence that an artifact is safe. Deleted or renamed filesystem entries remain part of the event history rather than being silently removed from it.

Validation covers real directory scale, concurrent initialization, reopen idempotence, file/directory session isolation, selection of directory targets, session-inside-target rejection, asynchronous rescan success and cancellation, deleted-directory fallback, and independent investigation histories.
