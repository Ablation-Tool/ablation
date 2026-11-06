# Capability Reference

CEROTTO connects agent activity, host telemetry, and disk evidence for authorized incident investigations. Each capability below describes tested behavior. Implementation and test links are available from the numbered references in the [README capability tables](../README.md#capabilities).

## Agent & Host Evidence Collection

### Agent Event Ingestion

Imports conversations, prompts, tool calls, processes, file events, and network events from validated JSONL records.

### Linux Audit Attribution

Correlates interleaved audit records into process execution, file activity, and network connections with PID/PPID attribution.

### Raw Disk Timelines

Collects allocated and deleted filesystem records without mounting or modifying the image.

### Verified EWF Collection

Requires successful `ewfverify`, preserves `ewfinfo`, hashes EWF segments, and processes E01 evidence through The Sleuth Kit.

### Controlled File Carving

Runs Foremost or Scalpel, preserves logs, and catalogs recovered files with hashes and acquisition provenance.

## Correlation & Artifact Handling

### Versioned Evidence Store

Stores cases, sources, and normalized events in SQLite with schema migrations and transactional writes.

### Deterministic Timelines

Correlates conversation-linked and same-host activity by UTC time range, host, process, and parent process.

### Case Manifests

Exports evidence paths, hashes, sizes, commands, tool versions, acquisition times, and collection status.

### Evidence Verification

Recomputes source and preserved-output hashes and reports missing or modified artifacts.

### Hash-Verified Artifact Inspection

Revalidates carved files before bounded hex or base64 JSON inspection. Recovered content is never executed.

## Analysis & Reporting

### Bounded LLM Analysis

Sends at most 500 metadata-only events to an OpenAI-compatible endpoint with timeouts and response limits.

### Citation Validation

Requires structured observations and hypotheses. Rejects invented event references and mismatched evidence counts.

### Portable Investigation Reports

Produces JSON or escaped Markdown reports that separate observations, hypotheses, limitations, and human review.

### Human Review Attestations

Records reviewer identity and decision. An attestation is not a cryptographic signature.

## Encrypted Vault & Forensic Tripwire

### Native GEMSEAL Containers

Implements GEMSEAL version 1 directly in C11 with exact little-endian file and record headers, HKDF-SHA256, ChaCha20-Poly1305, indexed nonces, previous-tag chaining, and authenticated END records. Supports empty, multi-record, exact-chunk, and randomized round trips, deterministic and reference interoperability vectors, strict corruption rejection, and atomic no-overwrite publication. The format is experimental and not independently audited.

### Native Vault Sensor

Writes native Linux inotify records directly into Cerotto's SQLite evidence store without JSONL ingestion. Supports recursive watches, open/read/modify/metadata/create/delete/move events, watcher sessions, sequence numbers, host and boot identifiers, raw masks, monotonic timestamps, and health events. Process and agent attribution remain unresolved unless independent evidence supports them.

### Plaintext Release Broker

Requires an explicit per-file decision, reason, permitted identity, separate owner-only release area, and expiration for approved releases. Records container and content hashes, requester, destination, release and expiration times, optional agent context, and cleanup state. Denials do not decrypt. Cleanup verifies content hashes and preserves modified releases with an explicit residual-plaintext record.

### Correlation and Response

Produces vault timelines, correlation documents, and reproducible custody exports. Agent attribution requires independent process and tool-call evidence. Network proximity is not treated as exfiltration proof. Approved response exports evidence before suspending a supplied process and records resume separately. No destructive automatic response is performed.

### Vault Case Workbench

Adds a dedicated Vault tab to CEROTTO GEM with native event filtering, status summaries, and a timeline for contacts, modifications, releases, health alerts, and response events. The database remains read-only in the GUI. Native C commands perform all state changes.

## Ablation + GEM Defense Research

### Accessible Volume Measurement

Computes accessible-volume threshold sweeps with strict probability cutoffs. Validates full distributions, rejects non-finite or unnormalized values, and records entropy, maximum probability, top-ten mass, vocabulary size, and probability-value hashes. The optional integration runs a real forward pass with hash-pinned DistilGPT2 ONNX artifacts.

### Native Accessible Volume

Implements the same strict threshold sweep in C. Accepts at most 100,000 finite, nonnegative probabilities, requires normalization within 1e-8, and records entropy, maximum probability, top-ten mass, and a SHA-256 digest of packed float64 values. No Python runtime or model runtime is required by the native measurement.

### Native Guarded Evidence Actions

Accepts a schema-version-1 JSON proposal for `query_timeline`, `get_event`, `get_manifest`, or `verify_case`. The guard verifies the expected case event count and forecast context hash inside a write transaction. It denies unsupported actions, stale case state, and forecast substitution before executing the action. Results use the same bounded C timeline, manifest, and verification implementations as the existing CLI.

### Guard Proposal Provenance

Registers the raw proposal as a `guard_proposal` evidence source with its path, size, and SHA-256 digest. Forecast, proposal, decision, and execution records link to that source. Duplicate action identifiers roll back the new evidence chain and source registration.

### Native GEM Workbench

Provides a native GTK3 desktop environment for Cerotto cases. The Lab groups defense evidence by action and supports text filtering, detailed event inspection, status summaries, a dedicated Vault timeline, and native Cairo accessible-volume charts. Header controls refresh the case, run native guard proposals, verify evidence, and export JSON reports. The database model is read-only; writes go through the C binary with fixed arguments and bounded output.

An optional VTE terminal embeds a user-selected interactive agent with case environment variables and bounded shutdown. The terminal is explicitly unguarded. GUI tests exercise the real application in isolated X11, including chart rendering, screenshot capture, report generation, and agent cleanup.

### Guarded GEM Execution

Binds each forecast to the exact GEM target, selected event, revision, and structured proposal. Supports snapshots, current-snapshot resolution, revision-checked work begins, and revision-checked exports. Denies unknown commands, unsupported fields, uncontrolled selection changes, stale revisions, out-of-scope references, and forecast substitution before executing the proposed action. The guard does not cover commands outside `GemCommandBroker`.

### Guard Evidence Chains

Produces `model_forecast`, `action_proposal`, `policy_decision`, and `execution_receipt` events. Shared identifiers link each chain. Denied actions have no execution receipt. Broker failures produce failed receipts rather than success claims. Accessible volume remains observational and has no authorization effect.

### GEM History Export

Converts selected GEM `events.jsonl` line ranges into validated Cerotto JSONL records. Preserves the complete GEM event in the details object and reports the next source line for incremental collection. Output files are created exclusively to prevent accidental overwrite.

## Security & Evidence Integrity

### No Model-to-Host Execution

Gives the LLM no shell, host credentials, forensic tools, database writes, or execution path.

### No-Shell Subprocesses

Executes forensic tools with fixed argument arrays, bounded output, and checked exit status.

### Evidence Hashing

Computes SHA-256 for source images, preserved output, EWF segments, and recovered artifacts.

### Transactional Ingestion

Rolls back malformed or duplicate records instead of accepting partial evidence sets.

### Hostile-Artifact Boundaries

Rejects symlinks and non-regular output, caps recovery size, and keeps recovered bytes out of LLM requests.

### Regression & Sanitizer CI

Tests real evidence workflows, failure paths, and normal/ASan/UBSan builds on every push and pull request.
