# Known Anomalies: Streaming Xilinx WDB

## Profile and metadata

- The legacy two-section layout has no embedded `Xilinx ISim DBG 006` database. Root indices and storage IDs are therefore not signal names and must not be presented as such.
- The newer three-section path is event-only. It does not reproduce the full modern DBG/RTTI name/type mapping; use the pinned full reader for that profile.
- WDB is proprietary. The accepted layouts are characterized profiles, not a promise that every Vivado release uses identical structures.
- Picosecond timestamps apply to the characterized XSim event ticks. Do not transfer that scale to an uncharacterized database without evidence.

## Event interpretation

- Independent roots are not globally timestamp-sorted. Merge with explicit time ordering if a combined timeline is required.
- Payload previews can be truncated; `payload_bytes` records the real length and `payload_truncated` records preview truncation.
- Waveform presence is not transaction success. Use the archived simulator log and independent focused RTL checks to establish functional outcomes.
- Root/storage IDs can change across builds and are not stable cross-version identifiers.

## Safety and completeness

- Decompression, page, chain, event, stream, file-size, and export limits fail explicitly. A limit error invalidates the summary rather than making it complete.
- JSONL uses an atomic temporary-file rename, but successful export does not imply the whole WDB was exported when `max_events` was reached; inspect `complete_within_limit`.
- Event iteration can discover corruption after earlier valid events. Trust the final completed summary/export, not a partially consumed stream as a success claim.
- Memory mapping bounds address space, not I/O time. The 10.76-million-event integration is expected to take longer than synthetic tests.
