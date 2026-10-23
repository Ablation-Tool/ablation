# DependencyConfusionScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Extract dependency confusion attack surface from compiled binaries.** Build systems embed registry URLs, package cache paths, and internal package names as strings in the final binary. These strings reveal which internal package names could be registered on public package managers to mount a dependency confusion attack. `DependencyConfusionScanner` searches the raw binary for 4 signal types: 8 private registry URL patterns covering Artifactory, JFrog, Azure Artifacts, AWS CodeArtifact, and GitHub Packages; public registry URL co-presence with a private one (indicating mixed registry configuration), build cache paths that expose internal package identifiers, and scoped npm package names matching the `@company/package` pattern.

## Usage

```python
from modules.dependency_confusion_scanner import DependencyConfusionScanner

scanner = DependencyConfusionScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = DependencyConfusionScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: DepConfusionFinding

| Field | Type | Description |
|-------|------|-------------|
| `finding_type` | str | Signal type (see table below) |
| `detail` | str | The matched URL, path, or package name |
| `severity` | str | `HIGH`, `MEDIUM`, or `LOW` |

## Finding types

| Type | Severity | What it detects |
|------|----------|-----------------|
| `private_registry` | HIGH | URL matching a private package registry pattern |
| `public_registry_ref` | HIGH | Public registry URL present alongside a private registry URL (mixed config) |
| `internal_package` | MEDIUM | Scoped npm package name in `@company/package` format |
| `build_path` | LOW | Build cache path exposing internal dependency layout |

## Private registry patterns

Artifactory, Nexus, JFrog Cloud, Azure DevOps Artifacts, AWS CodeArtifact, GitHub Package Registry (Maven and npm).

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on synthetic binary with JFrog URL and `@mycompany/utils` package name: 2 HIGH findings and 1 MEDIUM finding emitted.

## See also

- [SBOMExtractor](sbom-extractor.md): full component and version inventory
- [ThirdPartyLibraryIdentifier](third-party-library-identifier.md): FLIRT-signature-based library detection
- [BuildProvenanceExtractor](build-provenance-extractor.md): compiler and build chain identification
