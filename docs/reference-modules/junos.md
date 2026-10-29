# Junos firmware workflows

`ablation junos` provides safe Junos package extraction, detached-signature verification, filesystem inventories, and cross-version diffs. Targeted workflows compare bounded MIPS functions, validate and serialize VRF gencfg messages, analyze pointer ownership, and map gencfg provenance and authorization. Package scripts and Junos executables are never run on the analysis host, and filesystem mounting is not required.

## Why this is a layered workflow

A Junos package is not immediately a set of analyzable executables. Archive safety, payload integrity, signature verification, ISO recovery, and program semantics are separate questions. The workflow keeps them separate so a successful extraction is not confused with a trusted package, and a verified package is not confused with safe code.

Users gain a reproducible path from vendor archive to file inventory, release comparison, and architecture-aware review. The container and signature components provide evidence for later stages; the target pack supplies reusable MIPS/o32 and IPC context for deeper analysis. Each layer can be extended or replaced as another package layout or platform is validated, without making unsupported formats appear trusted or complete.

## Extract a package

```bash
ablation junos extract junos-srxsme-15.1X49-D170.4-domestic.tgz work/D170.4
```

The extractor validates archive paths, verifies embedded SHA-1 manifests, decodes Juniper's block-compressed ISO container, and extracts the ISO9660/Rock Ridge userland. Outputs are:

- `package/`: safely unpacked top-level files
- `payload.iso`: recovered ISO9660 image
- `root/`: extracted userland
- `metadata.json`: package, payload, ISO, and hash metadata

Use `--no-iso` to stop after recovering `payload.iso`.

The compressed container uses big-endian block tables and raw-deflate blocks of up to 64 KB. Kernel-composite images with the `55 aa 06 43` prefix are detected automatically. `modules/junos_compressed_iso.py` remains available as a compatibility entry point.

## Verify hashes and signatures

```bash
ablation junos verify work/D170.4/package --json signatures.json
ablation junos verify work/D170.4/package --require-all
```

Verification reports separate results for embedded payload hashes, detached signatures, and certificate chains. Both RSA and EC `JUNOS SIGNATURE` containers are supported through the system OpenSSL CLI. `--require-all` returns a nonzero status if any hash, signature, or chain fails. A failed or unsupported signature is never treated as successful.

## Build an inventory

```bash
ablation junos inventory work/D170.4/root --json D170.4.manifest.json
```

The manifest streams file hashes and records file type, size, mode, ELF status, and symlink targets.

## Compare releases

```bash
ablation junos diff work/D160.2/root work/D170.4/root --json diff.json
ablation junos diff work/D160.2/root work/D170.4/root \
  --functions usr/sbin/fwauthd --json fwauthd-diff.json
ablation junos diff work/D160.2/root work/D170.4/root --top-k 3 --json top-changes.json
```

The default diff classifies added, removed, changed, and unchanged files and ranks changed ELFs by size delta. `--functions` performs ELF import/string and function-level comparisons for named relative paths. `--top-k` selects the largest changed ELFs. Function matching uses exported names first, then normalized instruction signatures with addresses and immediates suppressed. Release timestamps, build paths, version strings, and build IDs are not treated as substantive string changes.

Deep diffs are bounded to selected targets; they do not run an unscoped semantic sweep across the firmware.

For a targeted comparison that does not build whole-binary context, supply both function addresses and optional byte sizes:

```bash
ablation junos function-diff old/flowd new/flowd 0x187aff44 0x18821924 \
  --old-size 1020 --new-size 1020 --cache function-cache --json vrf-diff.json
```

The bounded differ normalizes immediates, function-relative branches, and external calls, and reports direct callees separately. Results and cache writes are atomic; cache keys include both file hashes, addresses, and sizes. Oversized functions are rejected rather than silently truncated. Normalized equality is not a semantic-equivalence proof.

## MIPS instruction set and ABI

Junos platforms can use different architectures. The SRX Octeon userland uses **MIPS64r2 instructions with the 32-bit o32 ABI**, not the 64-bit N64 ABI. `ablation analyze` reports these separately:

```text
ISA/ABI: mips32/o32 (mips64r2 instructions, big-endian)
```

`window` uses a pure-ELF MIPS path for Junos binaries whose FreeBSD `DT_REL` metadata is unsupported by LIEF. `profile` uses o32 register and call-site annotation. `mips` selects the 32-bit tracker; `mips64` is reserved for N64 targets.

## Junos target pack

The target pack reuses platform metadata and IPC schemas instead of rediscovering them per binary. `ablation/profiles/junos-octeon-o32.yaml` selects the pure-ELF MIPS window, o32 annotator, and GOT-aware string resolver.

```bash
ablation junos target usr/sbin/flowd_octeon
ablation junos xrefs usr/sbin/flowd_octeon "Invalid blob size"
ablation junos overlay usr/sbin/nsd
```

`xrefs` resolves PIC and non-PIC function prologues, constant-base loads, and large static `.text` sections with undecodable words skipped. `overlay` persists only underscore-containing C symbols recovered from trace strings through `BinaryContext.set_names_bulk()`; free-form log messages are not registered as function names.

## gencfg messages and provenance

Versioned gencfg schemas live in `ablation/data/junos_gencfg.json`. Validate or construct a VRF-group message with:

```bash
ablation junos gencfg --list
ablation junos gencfg <hex-message>
ablation junos gencfg --encode --group-id 7 --operation 2 --vrf 10 --vrf 20
```

Validation reports named checks and actual field values, not just a boolean. The VRF schema distinguishes major type `0x8a` from `0x89`, decodes nested entries, and checks declared counts, entry types and lengths, forward progress, bounds, available bytes, and 32-bit length arithmetic. Add and change operations require a blob. The serializer emits fixed type-2, eight-byte VRF entries. Structural validity does not establish authorization or external reachability.

A provenance specification defines `nodes` and `edges`. Nodes name a binary, function address, size, and optional `producer` or `consumer` role. Edges can be `direct_call`, `indirect_call`, `transport`, or another declared relationship. Build the graph with:

```bash
ablation junos gencfg-graph work/D170.4/root provenance.json --json graph-report.json
```

Direct edges verify the target at the call site. Indirect edges verify only the `jalr` call site and leave the PIC target explicitly declared. Authorization evidence, transport details, reachability limits, and `runtime_unknowns` are preserved in the report. The static graph cannot enumerate runtime daemon credentials or routing-policy registrations.

For a focused caller and argument-provenance pass, use:

```bash
ablation junos provenance-slice usr/sbin/flowd_octeon_hm 0x1868c080 \
  --args a1,a2 --back 64 --json policy-callers.json
```

`provenance-slice` verifies direct JAL callers in executable segments and traces call arguments backward through register copies, arithmetic, loads, and stores, including the call delay slot. Each slice stops at a control-flow join or its instruction budget. This deliberately avoids treating one linear path as proof at a join; continue with targeted CFG review, producer serializers, and transport-specific authorization evidence. Indirect registrations and runtime credentials remain unknown unless separately established.

## MIPS ownership analysis

An ownership specification selects bounded functions and their roles:

```json
{
  "functions": [
    {"name": "add_vrfs", "va": "0x187aff44", "size": 1020, "may_free_arg0": true},
    {"name": "handler", "va": "0x187b0a40", "size": 1708},
    {"name": "defer", "va": "0x187b055c", "size": 696, "role": "deferred_callback"}
  ]
}
```

Run it with path and instruction budgets:

```bash
ablation junos ownership usr/sbin/flowd_octeon_hm ownership.json \
  --max-paths 256 --max-steps 20000 --json ownership-report.json
```

The analyzer tracks allocation, frees, pointer clearing, memory dereferences, callee-may-free events, and global roots across deferred callbacks. Optional `free_functions`, `allocator_functions`, `free_names`, and `allocator_names` fields extend the default models. Reports identify truncated analyses and label findings as static candidates; global table entries are collapsed by root, and indirect calls require manual review.

Function boundaries, indirect calls, vendor library wrappers, and depth-limited taint results still require manual review. Extraction and signature validation do not establish that a package is safe, and zero taint findings do not prove absence of vulnerabilities.
