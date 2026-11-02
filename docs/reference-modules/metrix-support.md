# METRIX support

## Purpose and distinction

METRIX is the inventory and navigation support package bundled with GUIAI. It helps turn a material directory into searchable artifact records and corpus summaries. It is not identical to the GUIAI investigation workbench: GUIAI adds the agent-driven Lab, project memory, visual investigation tree, and embedded real CLI.

METRIX is supporting infrastructure, not a second built-in AI or a replacement for GUIAI's event history. No separate METRIX checkout is required.

## Inventory and summaries

`metrix scan` inventories a material directory, writes artifact records and a summary, and generates a matrix view. It records metadata such as paths, formats, architectures, artifact classes, sizes, hashes, and analysis status where available.

```bash
metrix scan /path/to/material --output /path/to/metrix-output
metrix summary --output /path/to/metrix-output --text
```

Summary output can be JSON or human-readable text. It distinguishes artifact totals, regular files, directories, symlinks, hashed files, total bytes, and errors. Metadata is not proof of reverse-engineering coverage or a vulnerability verdict.

## Queries and retrieval

`metrix query` filters records by format, architecture, artifact class, status, and analysis status. Repeated `--contains` terms are case-insensitive and all must match. Output is JSONL by default or TSV with `--tsv`.

```bash
metrix query --output /path/to/metrix-output \
  --architecture arm64 --status not_started --contains parser --limit 20
```

The default query limit is 50. `--limit 0` explicitly requests unlimited output, preserving the user's choice between a focused retrieval and a complete export.

`metrix show` retrieves one artifact by ID, path, or unique hash prefix. Missing or ambiguous identifiers produce an error rather than selecting an arbitrary artifact. `metrix render` regenerates the matrix from existing records.

## Native dashboard and external agent

`metrix desktop` opens the native artifact dashboard with an optional embedded interactive CLI. The `gui` command can serve the local dashboard on loopback and optionally connect an external agent command; `--no-browser` disables automatic browser opening.

The external `AgentBridge` is a read-only request path for chat, active filters, recent chat, and explicitly selected artifact records. It uses the external CLI's own model, authentication, permissions, and data policy. It is separate from GUIAI's full interactive investigation workspace.

Custom commands can contain `{prompt}` for substitution; otherwise the prompt is sent through stdin. Agent timeout and error output are reported instead of being presented as successful analysis.

## Packaging and implementation

The `guiai-lab` distribution bundles `metrix` and its Python dependencies. `pyte` supports the native terminal parser, and `wcwidth` supports display-width calculations. The offline native GUIAI packages include these wheels; optional full Ablation analysis dependencies are separate.

Implementation map:

- `guiai-lab/metrix/inventory.py`: artifact inventory and metadata
- `guiai-lab/metrix/render.py`: summary loading and matrix generation
- `guiai-lab/metrix/cli.py`: scan, summary, query, show, render, GUI, and desktop commands
- `guiai-lab/metrix/agent.py`: command parsing and external read-only agent bridge
- `guiai-lab/metrix/desktop.py`: native dashboard, terminal display, and PTY/ConPTY handling
- `guiai-lab/metrix/server.py`: loopback dashboard service

## Limits and validation

Inventory status and analysis status answer different questions. A format match, architecture label, file count, or matrix score is not proof of complete analysis, public novelty, exploitability, or vulnerability. Artifact contents and embedded text remain untrusted data.

Validation covers native dashboard startup, terminal interaction, process cleanup, output draining, directory workspace handling, and offline installation. Corpus-specific accuracy and analysis coverage still require actual tool evidence and human review.
