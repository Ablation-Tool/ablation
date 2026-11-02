# GUIAI Performance and Investigation Memory

## The problem GUIAI solves

GUIAI primarily solves **investigation memory and coordination**, not raw analysis speed. Ablation and the real agent CLI still perform the actual reverse engineering.

With CLI alone, an AI Agent can analyze material, but the human must remember what was completed, which branches remain untouched, where evidence was saved, and how to reconstruct a stopped session. That makes the human the session database and encourages repeated scans, repeated prompts, and duplicated work.

GUIAI puts that information into a visible, resumable workspace. The workspace remembers; the CLI supplies labor; the human supplies direction and judgment. This is the project's [Unified Memory Architecture](unified-memory-architecture.md).

## How GUIAI improves the process

### Less rediscovery

The agent can read `guiai state` and `guiai tree` instead of replaying an entire conversation or rescanning a directory. A selected function, artifact, or evidence node provides a precise starting point for the next task.

### Less memory burden

The Lab shows which items are not started, in progress, partial, blocked, reviewed, complete within a scope, rejected, or not applicable. The human can see what needs work rather than relying on a mental map of a long RE session.

### Faster direction and handoffs

Selecting a node and saying “work more on this” is more reliable than reconstructing its entire history in natural language. Project files preserve discoveries, selections, bookmarks, terminal directories, active Labs, and preferences so another session or agent can continue from recorded evidence.

### Less context switching

The real interactive CLI runs beside the Lab. The user can inspect the tree, choose the next target, and direct the agent in one native window rather than coordinating a separate terminal and dashboard.

### Better review, not just more output

Evidence paths, explicit review states, follow-up prompts, and append-only undo make it easier to distinguish an interesting observation from a reviewed result. Status and chart geometry do not substitute for evidence or prove analysis coverage.

## Example: from terminal output to a resumable Lab

Suppose an agent identifies 200 functions in a firmware image. With CLI alone, the user might scroll through the output, forget which functions were completed, and ask the agent to identify them again later.

With GUIAI, those functions become nodes in the Lab. The user can see untouched branches, select a suspicious function, and direct the agent to continue from its recorded evidence. A new agent reads the same session state rather than replaying the entire investigation.

The time saved is in locating work and avoiding repeated analysis, not in executing disassembly or taint analysis faster.

## What performance means here

Potential improvements come from **less redundant work**, not weaker analysis:

- Fewer repeated directory scans and rediscovered branches.
- Less context spent reconstructing prior work.
- Less time finding the next untouched item or relevant evidence.
- Fewer manual path copies and fewer transitions between separate tools.
- More reliable resumption after a pause, a new agent, or a change of investigator.

[Token Allocation](guiai-token-allocation.md) explains how scoped retrieval can reduce unnecessary context while keeping full evidence available on disk. It is not a promise of a particular token or cost reduction.

## What GUIAI does not change

GUIAI does not make disassembly, taint analysis, or model reasoning inherently faster. It does not guarantee complete coverage, confirm a vulnerability, serialize an AI model's conversation, or replace the agent's own permissions and provider policy.

## When CLI alone is better

CLI remains the right choice for one-off commands, automation, headless environments, and small tasks where a full investigation workspace would add unnecessary overhead. GUIAI is most useful for large, long-running, or multi-part investigations that need navigation, memory, and human review.

## Implementation evidence

- `guiai-lab/guiai/events.py`: authoritative event history and selection state.
- `guiai-lab/guiai/cli.py`: targeted `state`, `tree`, `emit`, and `emit-many` operations.
- `guiai-lab/guiai/app.py` and `guiai-lab/guiai/gtk_app.py`: visual navigation, project actions, and embedded agent lifecycle.
- `guiai-lab/guiai/preferences.py`: persistent terminal and workspace preferences.
- `guiai-lab/metrix/desktop.py`: interactive terminal I/O and process cleanup.

For the persistence model, see [Project Memory](guiai-project-memory.md). For the terminal and agent bridge, see [AI Agent Bridge](guiai-agent-bridge.md).

## Measuring the benefit

Evaluate GUIAI by investigation outcomes, not by claims of faster computation: time to find the next untouched branch, number of repeated scans or prompts, time to resume an old project, evidence traceability, and duplicated or forgotten work. Those measurements show whether the workspace is improving coordination without reducing evidence quality or investigation quantity.
