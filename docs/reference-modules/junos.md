# Junos firmware workflows

`ablation junos` provides safe Junos package extraction, detached-signature verification, filesystem inventories, and cross-version diffs. Package scripts and Junos executables are never run on the analysis host, and filesystem mounting is not required.

## Extract a package

```bash
ablation junos extract junos-srxsme-15.1X49-D170.4-domestic.tgz work/D170.4
```

The extractor validates archive paths, verifies embedded SHA-1 manifests, decodes Juniper's block-compressed ISO container, and extracts the ISO9660/Rock Ridge userland. Outputs are:

- `package/` — safely unpacked top-level files
- `payload.iso` — recovered ISO9660 image
- `root/` — extracted userland
- `metadata.json` — package, payload, ISO, and hash metadata

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

## MIPS instruction set and ABI

Junos platforms can use different architectures. The SRX Octeon userland uses **MIPS64r2 instructions with the 32-bit o32 ABI**, not the 64-bit N64 ABI. `ablation analyze` reports these separately:

```text
ISA/ABI: mips32/o32 (mips64r2 instructions, big-endian)
```

`window` uses a pure-ELF MIPS path for Junos binaries whose FreeBSD `DT_REL` metadata is unsupported by LIEF. `profile` uses o32 register and call-site annotation. `mips` selects the 32-bit tracker; `mips64` is reserved for N64 targets.

Function boundaries, indirect calls, vendor library wrappers, and depth-limited taint results still require manual review. Extraction and signature validation do not establish that a package is safe, and zero taint findings do not prove absence of vulnerabilities.
