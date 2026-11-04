# Unified Memory Architecture

GEM's **Unified Memory Architecture (UMA)** is a project-specific way of organizing reverse-engineering work. It unifies the GEM workspace, the real CLI/AI Agent, and the human investigator around one authoritative investigation state.

UMA is not a hardware memory standard, an operating-system memory manager, or a promise that an AI model retains its chat history. It describes how labor, navigation, memory, and judgment are separated without losing their connection to the same investigation.

## Workspace as address space

The GEM workspace is the investigation's **address space**: the durable, navigable representation of what has been discovered, what remains untouched, and what the human wants to inspect next.

It stores:

- Target identity and the real top-level directory inventory.
- Append-only discovery events and their parent/child relationships.
- Current status, evidence paths, notes, hypotheses, findings, and scope.
- Selected nodes, bookmarks, Lab sessions, and terminal directories.
- Project manifests, active Lab state, and workspace preferences.

The tree, breadcrumbs, Rings, and Treemap are views of that state. They let the human and the agent find the same work without repeatedly reconstructing it from chat history or a directory listing. Chart geometry represents subtree node count, not analysis coverage or disk usage.

The workspace is not a second agent-memory database. The event log is authoritative; the tree is a view of that history. The latest event for an ID determines its current state while earlier events remain available for audit.

## CLI as processor

The CLI/AI Agent is the **processor** that performs work within that address space. It can inspect artifacts, invoke Ablation and other tools, test hypotheses, and record supported discoveries through the GEM CLI.

The agent reads current state with commands such as `gem state` and `gem tree`, then records results with `gem emit` or `gem emit-many`. Its own conversation context is not authoritative. An agent can be replaced or restarted without discarding the investigation's recorded memory.

The CLI supplies labor, not a guarantee of correctness or persistence. Observations, hypotheses, tool evidence, and human-confirmed findings remain distinct.

## Human as controller

The human is the **controller and director**, not the session database. The human supplies direction, priorities, and judgment that the workspace and agent cannot supply on their own.

Through the workspace, the human can:

- Select a node and direct the agent to continue there.
- Flag follow-up work or mark a node reviewed.
- Filter the tree, inspect evidence, and open a focused prompt in the CLI.
- Correct or append to the investigation state rather than relying on memory of a long session.
- Decide whether an agent's hypothesis is supported and what should happen next.

UMA reduces the human's need to remember what has already been explored. It does not remove the need for human review, authorization, or technical judgment.

## Unification flow

The three roles form one feedback loop:

1. The human selects a target and a project directory.
2. The workspace creates the authoritative session and top-level inventory.
3. The CLI/AI Agent reads the selected state and performs actual analysis.
4. The agent records evidence, limitations, and new branches through the GEM CLI.
5. The workspace propagates those events into the tree, charts, details, and status summaries.
6. The human selects the next area to investigate, requests follow-up, or marks a reviewed result.
7. The agent resumes from that shared state instead of rediscovering the session.

The result is a **unified investigation address space**: the workspace remembers, the CLI works, and the human directs. GEM is the presentation and coordination layer that connects those roles.

## Consistency and state

Each Lab has its own event history and selection state. Sessions and selection files are not shared between independent investigation tabs.

- Event reads use shared locks; event writes use exclusive locks.
- Selection state and the project manifest are written atomically.
- Replaying an identical event is a no-op; a newer event for the same ID supersedes the older state without deleting history.
- Parent IDs and event cycles are validated to prevent orphaned or cyclic branches.
- A parent's own status is not inferred from its children.
- Corrupt files produce visible errors rather than silently replacing evidence.

This is the consistency model that lets the workspace serve as memory for both the human and the agent.

## Boundaries

UMA does not mean:

- Every operation is complete or every artifact has been analyzed.
- An AI Agent's chat or model context is serialized as project memory.
- A directory's top-level inventory proves recursive coverage.
- An agent observation is automatically a confirmed vulnerability.
- GTK's independent Lab tabs are available in the single-investigation Tk interface.

The live process and terminal scrollback are not the authoritative project record. The recorded Lab history and current selection are the supported continuation state.

## Code map

| Role | Implementation |
|---|---|
| Authoritative session and event model | `gem-lab/gem/events.py` |
| Tk investigation and selection interface | `gem-lab/gem/app.py` |
| GTK multi-Lab workspace and native terminal | `gem-lab/gem/gtk_app.py` |
| Agent-facing state and discovery commands | `gem-lab/gem/cli.py` |
| Tk terminal and POSIX PTY support | `gem-lab/metrix/desktop.py` |
| Persistent workspace layout | `gem-lab/gem/layout.py` and `gem-lab/gem/preferences.py` |
| Complete Ablation and GEM installation | `gem-lab/packaging/forall.py` |

See the [GEM workbench guide](../../gem-lab/README.md) for the session-file layout, agent commands, and native platform behavior.
