# Artifact inventory and RE coverage

**File:** `ablation/analyzers/artifact_inventory.py`

## Why this exists

Large firmware collections need an explicit inventory before anyone can claim complete review. `scan_artifacts()` records every file, detects duplicates and incomplete downloads, and compares literal artifact names with an RE evidence corpus.

Coverage is deliberately conservative: **`referenced` means the artifact path or unique basename occurs in the records. It does not prove completed analysis or a security verdict.**

## Usage

```python
from ablation.analyzers.artifact_inventory import (
    inventory_to_dict,
    markdown_report,
    scan_artifacts,
)

inventory = scan_artifacts("/path/to/artifacts", "/path/to/re-records", hash_files=True)
print(inventory.summary)

json_payload = inventory_to_dict(inventory)
markdown = markdown_report(inventory)
```

CLI:

```bash
python -m ablation.analyzers.artifact_inventory /path/to/artifacts \
  --records /path/to/re-records --hash \
  --json coverage.json --markdown coverage.md \
  --archives --nested-json nested.json --nested-markdown nested.md
```

Hashing is optional because it requires reading every non-sensitive regular file. Files are streamed in 1 MiB chunks rather than loaded into memory. `--archives` additionally requires both nested output paths.

## Coverage model

| Field | Meaning |
|---|---|
| `path` | POSIX-style path relative to the artifact root |
| `size` | File size from `lstat`, in bytes |
| `extension` | Lowercase final suffix, or `<none>` |
| `handler` | Direct registered analyzer, otherwise `none` |
| `status` | `incomplete`, `referenced`, or `unreviewed` |
| `duplicate` | Whether another artifact has the same SHA-256 |
| `metadata_only` | Content was not read because of sensitivity, file type, or an error |
| `sha256` | Content digest when hashing was enabled and permitted |
| `evidence` | Evidence filenames containing the literal path or unique basename |
| `kind` | `file`, `symlink`, or `other` |
| `error` | Per-artifact stat/hash error, if any |

A missing handler means no direct registry entry, not that analysis is impossible. Duplicate and incomplete states are independent of evidence coverage; incomplete status takes precedence in the final status field.

## Evidence matching

Evidence is loaded only from top-level `*.py` and `*.md` files in the selected records directory. Generated `*_artifact_coverage.md` and `*_nested_coverage.md` matrices plus `coverage_re.py` summaries are excluded so previous reports cannot mark their own remaining-work queues as prior analysis. Matching uses:

- The complete relative artifact path; or
- A basename only when it is unique in the artifact inventory, at least five characters long, and not a generic coverage term such as `nested`, `coverage`, `artifact`, or `artifacts`.

This avoids treating generic names, directory names, or repeated basenames as evidence. An evidence match should be reviewed manually before converting `referenced` into a stronger completion claim.

## Nested archive coverage

`scan_nested_artifacts(root, records)` enumerates regular members from tar, tar.gz, tar.bz2, tar.xz, ZIP, and XSA containers without extracting them. Every `ArchiveMember` retains its `container`, member `path`, `virtual_path`, size, status, and evidence. `nested_inventory_to_dict()` and `nested_markdown_report()` produce separate nested reports.

Member and container coverage are independent. One referenced member does not prove that the complete archive was analyzed. Links and special files are skipped, unsafe member paths and per-archive errors are recorded, and generated nested reports do not alter top-level statuses or hashes.

Archive limits are 10,000 containers, 100,000 members per container, and 1,000,000 total members. Top-level evidence matching and nested member matching share the same single-pass implementation.

## Safety and limits

- Directory symlinks are not followed. File symlinks are recorded as metadata-only entries.
- Well-known secret and credential files are inventoried by metadata but never opened for hashing.
- Evidence limits: 10,000 files, 32 MiB per file, 256 MiB total.
- Inventory limits: 1,000,000 artifacts and 4,096 characters per relative path.
- Walk and per-file errors are preserved without silently discarding the rest of the inventory.
- JSON and Markdown output is deterministic for identical inputs and does not embed a timestamp.

## Reports

`inventory_to_dict()` returns the root, evidence root, summary, errors, and complete artifact list. `markdown_report()` produces a summary, top-level directory counts, and the complete coverage matrix. Summary counters include statuses, extensions, handlers, duplicate groups/files, metadata-only files, and scan errors.

The JSON is the machine-readable source for subsequent prioritization. The Markdown is a review aid, not a substitute for reading the referenced RE evidence.

## Validation and FORGE

Tests cover literal and ambiguous evidence matching, duplicate content, incomplete downloads, repeat-scan evidence exclusion, symlink avoidance, metadata-only sensitive files, invalid roots, handlers, and deterministic output. `FORGE.audit_module()` and the SAFE CODE 10-section review pass with zero findings.

## See also

- [DiskImageExtractor](disk-image-extractor.md)
- [VersalPdi](versal-pdi.md)
