# Encrypted vault and forensic tripwire

Cerotto provides native GEMSEAL version 1 containers, encrypted canaries, Linux inotify monitoring, an explicit plaintext-release broker, conservative correlation, and reproducible custody exports. The implementation is part of the C11 core and SQLite evidence store. It does not require the GEMSEAL Python package, a plugin, a sidecar, or a JSONL handoff.

GEMSEAL is experimental and has not received an independent cryptographic review. For production confidentiality, use an audited format such as `age`. The sensor can watch directories containing any encrypted format. The release broker currently decrypts only GEMSEAL version 1.

## Security boundaries

- Store keys and the evidence database outside the watched vault.
- Use owner-only files and directories on a permission-enforcing filesystem. Cerotto requests `0600` files and `0700` directories and rejects inaccessible key files with group or other permissions. Mount-specific behavior can still weaken this boundary.
- Keep the key authority outside the agent's access path. Cerotto does not provide unattended AI access to it.
- A same-user agent may be able to stop the sensor, alter evidence, access keys, or read approved plaintext. Use separate identities and protected or remote evidence replication for stronger boundaries.
- Encryption does not create logs, inotify does not block access, and an open event does not prove malicious intent.
- Inotify does not provide a PID, UID, executable, syscall, or agent identity. Those fields remain unresolved unless independent audit or agent records support correlation.
- Directory enumeration, alternate mount paths, hard links, raw-disk access, snapshots, network filesystems, FUSE variants, and VM-internal activity may escape monitoring. Queue overflow creates a coverage gap.
- Root, kernel, hypervisor, firmware, and physical compromise are outside the security boundary.

## Native container operations

Generate a 32-byte random key:

```bash
build/cerotto keygen --output /safe/private/vault.key
```

Encrypt and decrypt through the operator commands:

```bash
build/cerotto encrypt --key /safe/private/vault.key \
  --input plain.bin --output container.gemseal --chunk-size 4096

build/cerotto decrypt --key /safe/private/vault.key \
  --input container.gemseal --output restored.bin
```

The implementation uses explicit little-endian fields, a 48-byte file header, 16-byte record headers, HKDF-SHA256, ChaCha20-Poly1305, indexed nonces, previous-tag chaining, and an authenticated empty END record. It rejects wrong keys, unsupported versions and suites, malformed lengths, empty DATA records, invalid indices, modification, reordering, truncation, and trailing bytes. Publication is atomic and no-overwrite after complete verification. Temporary files can remain after uncatchable termination or power loss and require manual review.

The deterministic 115-byte vector in the GEMSEAL format specification decrypts to ASCII `GEM`. Cross-compatibility has been exercised in both directions with the reference Python implementation.

No passphrase mode is provided. HKDF is not a password-stretching function, and plain SHA-256 is not accepted as a secure password KDF.

## Create a native vault

Initialize the case database first:

```bash
build/cerotto init --db case.db

build/cerotto vault init --db case.db --case incident-7 \
  --vault /safe/vault --key /safe/private/vault.key --host agent-vm-1
```

Initialization refuses existing paths, requires the key and database outside the vault, and creates an encrypted canary. The native `vault.initialized` event includes the container hash, key-custody state, vault ID, host, boot ID, and evidence timestamps. It does not include key bytes or the key path.

## Monitor a vault

Start monitoring before starting the agent:

```bash
build/cerotto vault watch --db case.db --case incident-7 \
  --vault /safe/vault --host agent-vm-1
```

The sensor recursively watches local directories and preserves open, read, modify, metadata, create, delete, move, close-write, queue-overflow, and watch-removal records. Startup, readiness, shutdown, degradation, and clock-divergence events use the same native evidence store. Raw source details include the inotify mask, watch descriptor, cookie, directory flag, and monotonic timestamp.

Each record contains:

- `observed_utc`: sensor observation time.
- `recorded_utc`: evidence-store commit time.
- `analysis_utc`: `null` until an analysis view is generated.
- Host, boot, vault, watcher-session, sequence, event, and path identifiers.
- Explicit `process`, `agent_session`, `tool_call`, `consent`, `plaintext_state`, and `attribution` values. Unsupported values remain `null` or `unknown`.

Records are not discarded for noise reduction. Alert presentation may be filtered separately.

Useful controls:

```bash
build/cerotto vault watch --db case.db --case incident-7 \
  --vault /safe/vault --host agent-vm-1 --duration 60 --max-events 100
```

`--duration` is a bounded monitoring interval in seconds. `--max-events` stops after the selected number of file events. Health records are not counted toward that limit.

Diagnostic options `--inject-overflow` and `--inject-clock-change` exercise health paths without claiming a real kernel overflow or host clock adjustment. `--fail-evidence-write` exercises the evidence-pipeline degradation path. These options are for controlled testing.

## Release plaintext

A denial records the request without decrypting or creating output:

```bash
build/cerotto vault release --db case.db --case incident-7 \
  --key /safe/private/vault.key --input /safe/vault/project_notes.gemseal \
  --output /safe/release/denied.bin --release-root /safe/release \
  --requester analyst --reason "unapproved test" --identity agent-test \
  --host agent-vm-1
```

An approved release requires an explicit decision, a separate owner-only release area, and an expiration:

```bash
build/cerotto vault release --db case.db --case incident-7 \
  --key /safe/private/vault.key --input /safe/vault/project_notes.gemseal \
  --output /safe/release/approved.bin --release-root /safe/release \
  --requester analyst --reason "approved forensic review" --identity agent-test \
  --host agent-vm-1 --expires 2026-11-04T00:00:00Z --approve
```

The broker records container and content hashes, requester, reason, decision, destination, permitted identity, release time, expiration, optional agent session and tool call, and cleanup state. It does not infer those optional fields. Publication failure removes newly created plaintext where possible.

Clean up an approved release:

```bash
build/cerotto vault cleanup --db case.db --case incident-7 \
  --release-id RELEASE_ID --approve --host agent-vm-1
```

Cleanup verifies the content hash before deletion. Modified content is retained and recorded as `modified_retained`. Already-absent content is reported as absent. Expiration does not automatically delete plaintext; cleanup is an explicit operator action.

## Timeline and correlation

Produce a vault timeline:

```bash
build/cerotto vault timeline --db case.db --case incident-7 \
  --output vault-timeline.json
```

Correlate one vault event:

```bash
build/cerotto vault correlate --db case.db --case incident-7 \
  --event-id VAULT_EVENT_ID --output correlation.json
```

Correlation searches independent process, agent tool-call, and network evidence in bounded windows. Labels have these meanings:

- `unresolved`: independent evidence is insufficient.
- `process_correlated`: a process record supports limited attribution.
- `agent_correlated`: process and agent tool-call records support moderate attribution.

Network proximity is labeled `contact_followed_by_network` when independently recorded network activity follows. It is not proof of exfiltration. Backup, antivirus, indexing, synchronization, administration, and approved jobs remain explicit benign alternatives.

## Evidence-first response

Suspension requires approval and a new evidence-export directory. Cerotto exports evidence before sending `SIGSTOP`:

```bash
build/cerotto vault respond --db case.db --case incident-7 \
  --event-id VAULT_EVENT_ID --pid AGENT_PID \
  --output response-evidence --approve --host agent-vm-1
```

Resume with `SIGCONT`:

```bash
build/cerotto vault resume --db case.db --case incident-7 \
  --event-id VAULT_EVENT_ID --pid AGENT_PID --approve --host agent-vm-1
```

These actions affect only the supplied process. They do not isolate networking or contain the agent. No destructive automatic response is performed.

## Custody export

```bash
build/cerotto vault export --db case.db --case incident-7 \
  --output vault-export --retention-days 30
```

The new directory contains `payload.json` and `custody.json`. The payload excludes export-time fields so repeated exports of unchanged evidence produce identical bytes and hashes. Custody records analysis time, exporter UID, retention setting, and payload SHA-256. Existing export directories are not overwritten.

## Security diagnostics

The diagnostics demonstrate weak manually derived keys, not a generic ChaCha20 attack:

```bash
build/cerotto crack wordlist --input container.gemseal \
  --wordlist words.txt --mode sha256

build/cerotto crack pin --input container.gemseal --digits 4

build/cerotto crack raw-prefix --input container.gemseal --variable-bytes 1
```

Supported candidate transforms are SHA-256, zero-padding, and exact raw 32-byte keys. Reports include tested and skipped candidates, elapsed time, candidates per second, and first-record authentication. `--output` additionally verifies the complete container after recovery. Do not present these bounded searches as a practical attack on a random 256-bit key.

## Verification

Run the complete project suites:

```bash
make clean && make && make check
make sanitize
make check BUILD_DIR=build/sanitize
```

Vault tests cover deterministic and cross-compatible encryption, malformed records, no-overwrite and interruption cleanup, real inotify access, repeated opens and an unrelated-file negative control, watcher health and restart, direct persistence, release and cleanup, modified-release retention, correlation requirements, response, export reproducibility, and bounded key-search diagnostics.

## Remaining risks and unverified platforms

- GEMSEAL remains experimental and has not received an independent cryptographic audit.
- Only Linux inotify monitoring is implemented and verified. Windows, macOS, network filesystems, FUSE variants, VM guests, and host bind-mount semantics require separate validation.
- Queue-overflow and clock-change tests use diagnostic injection. No claim is made that a real kernel overflow or host clock adjustment was forced.
- SIGKILL and power loss can leave temporary files. Owner-only modes depend on the filesystem.
- The evidence database is not inherently tamper-proof. Protected or remote replication is required when the agent can modify local evidence.
- A released plaintext file is no longer confidential. Approved access, expiry, cleanup, and residual-file state require operational review.
