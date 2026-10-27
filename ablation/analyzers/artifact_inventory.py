"""Read-only artifact inventory, duplicate detection, and RE evidence coverage."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional


MAX_FILES = 1_000_000
MAX_PATH_CHARS = 4096
MAX_EVIDENCE_FILES = 10_000
MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_TOTAL_BYTES = 256 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024

_HANDLERS = {
    ".pdi": "VersalPdi",
    ".bit": "XilinxBitfile",
    ".vhd": "VerilogSemantic",
    ".vhdl": "VerilogSemantic",
    ".v": "VerilogSemantic",
    ".htm": "HdlHtmlExtractor",
    ".docx": "DocxReExtractor",
    ".tex": "LatexReExtractor",
    ".cir": "SpiceAnalyzer",
    ".elf": "BinaryContext",
    ".wic": "DiskImageExtractor",
    ".img": "DiskImageExtractor",
}

_SECRET_NAMES = {
    ".env", "credentials", "secrets", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
}
_SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx"}


@dataclass
class Artifact:
    path: str
    size: int
    extension: str
    handler: str
    status: str = "unreviewed"
    kind: str = "file"
    duplicate: bool = False
    metadata_only: bool = False
    sha256: str = ""
    evidence: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class Inventory:
    root: str
    records: str
    artifacts: list[Artifact]
    errors: list[str]

    @property
    def summary(self) -> dict:
        statuses = Counter(artifact.status for artifact in self.artifacts)
        extensions = Counter(artifact.extension for artifact in self.artifacts)
        top_level = Counter(artifact.path.split("/", 1)[0] for artifact in self.artifacts)
        handlers = Counter(artifact.handler for artifact in self.artifacts)
        groups: dict[str, list[str]] = {}
        for artifact in self.artifacts:
            if artifact.duplicate and artifact.sha256:
                groups.setdefault(artifact.sha256, []).append(artifact.path)
        return {
            "files": len(self.artifacts),
            "bytes": sum(artifact.size for artifact in self.artifacts),
            "statuses": dict(sorted(statuses.items())),
            "top_level": dict(sorted(top_level.items())),
            "extensions": dict(sorted(extensions.items())),
            "handlers": dict(sorted(handlers.items())),
            "duplicate_groups": len(groups),
            "duplicate_files": sum(artifact.duplicate for artifact in self.artifacts),
            "metadata_only_files": sum(artifact.metadata_only for artifact in self.artifacts),
            "errors": len(self.errors),
        }


def _metadata_only(path: Path) -> bool:
    name = path.name.lower()
    return (
        name in _SECRET_NAMES
        or name.startswith(".env.")
        or path.suffix.lower() in _SECRET_SUFFIXES
    )


def _load_evidence(records: Optional[Path]) -> dict[str, str]:
    if records is None:
        return {}
    root = records.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"evidence path is not a directory: {records}")
    paths = sorted(
        (
            path for path in (*root.glob("*.py"), *root.glob("*.md"))
            if not path.name.endswith("_artifact_coverage.md") and path.name != "coverage_re.py"
        ),
        key=lambda path: path.name,
    )
    if len(paths) > MAX_EVIDENCE_FILES:
        raise ValueError("too many evidence files")
    evidence: dict[str, str] = {}
    total = 0
    for path in paths:
        size = path.stat().st_size
        if size > MAX_EVIDENCE_FILE_BYTES:
            raise ValueError(f"evidence file too large: {path}")
        total += size
        if total > MAX_EVIDENCE_TOTAL_BYTES:
            raise ValueError("evidence corpus too large")
        evidence[path.name] = path.read_text(encoding="utf-8", errors="replace")
    return evidence


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        while chunk := stream.read(HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def scan_artifacts(
    root: str | Path,
    records: str | Path | None = None,
    *,
    hash_files: bool = False,
) -> Inventory:
    root_path = Path(root).resolve(strict=True)
    if not root_path.is_dir():
        raise ValueError(f"artifact root is not a directory: {root}")
    evidence = _load_evidence(Path(records) if records is not None else None)
    artifacts: list[Artifact] = []
    errors: list[str] = []
    paths: set[str] = set()

    def on_error(error: OSError) -> None:
        errors.append(f"{error.filename or root_path}: {error.strerror or error}")

    for base, directories, filenames in os.walk(root_path, followlinks=False, onerror=on_error):
        directories.sort()
        filenames.sort()
        for name in filenames:
            path = Path(base, name)
            relative = path.relative_to(root_path).as_posix()
            if len(relative) > MAX_PATH_CHARS:
                errors.append(f"path too long: {relative[:256]}")
                continue
            if len(artifacts) >= MAX_FILES:
                raise ValueError(f"artifact inventory exceeds {MAX_FILES} files")
            paths.add(relative)
            extension = path.suffix.lower() or "<none>"
            artifact = Artifact(relative, 0, extension, _HANDLERS.get(extension, "none"))
            try:
                stat = path.lstat()
                artifact.size = stat.st_size
                if path.is_symlink():
                    artifact.kind = "symlink"
                    artifact.metadata_only = True
                elif not path.is_file():
                    artifact.kind = "other"
                    artifact.metadata_only = True
                elif _metadata_only(path):
                    artifact.metadata_only = True
                elif hash_files:
                    artifact.sha256 = _sha256(path)
            except OSError as error:
                artifact.error = str(error)
                artifact.metadata_only = True
            artifacts.append(artifact)

    basename_counts = Counter(Path(artifact.path).name for artifact in artifacts)
    patterns: dict[str, set[int]] = {}
    for index, artifact in enumerate(artifacts):
        if artifact.path.endswith(".aria2") or f"{artifact.path}.aria2" in paths:
            artifact.status = "incomplete"
            continue
        tokens = [artifact.path]
        basename = Path(artifact.path).name
        if basename_counts[basename] == 1 and len(basename) >= 5:
            tokens.append(basename)
        for token in tokens:
            patterns.setdefault(token, set()).add(index)

    transitions: list[dict[str, int]] = [{}]
    failures = [0]
    outputs: list[set[int]] = [set()]
    for token, indices in patterns.items():
        state = 0
        for character in token:
            state = transitions[state].setdefault(character, len(transitions))
            if state == len(transitions):
                transitions.append({})
                failures.append(0)
                outputs.append(set())
        outputs[state].update(indices)
    pending = deque([0])
    while pending:
        state = pending.popleft()
        for character, child in transitions[state].items():
            if state == 0:
                failures[child] = 0
            else:
                fallback = failures[state]
                while fallback and character not in transitions[fallback]:
                    fallback = failures[fallback]
                failures[child] = transitions[fallback].get(character, 0)
            outputs[child].update(outputs[failures[child]])
            pending.append(child)

    for name, text in evidence.items():
        state = 0
        for character in text:
            while state and character not in transitions[state]:
                state = failures[state]
            state = transitions[state].get(character, 0)
            for index in outputs[state]:
                artifacts[index].evidence.append(name)
    for artifact in artifacts:
        artifact.evidence.sort()
        if artifact.evidence:
            artifact.status = "referenced"

    groups: dict[str, list[Artifact]] = {}
    for artifact in artifacts:
        if artifact.sha256:
            groups.setdefault(artifact.sha256, []).append(artifact)
    for group in groups.values():
        if len(group) > 1:
            for artifact in group:
                artifact.duplicate = True

    return Inventory(str(root_path), str(Path(records).resolve()) if records is not None else "", artifacts, errors)


def inventory_to_dict(inventory: Inventory) -> dict:
    return {
        "root": inventory.root,
        "records": inventory.records,
        "summary": inventory.summary,
        "errors": inventory.errors,
        "artifacts": [asdict(artifact) for artifact in inventory.artifacts],
    }


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def markdown_report(inventory: Inventory) -> str:
    summary = inventory.summary
    lines = [
        "# Artifact coverage matrix",
        "",
        "Coverage is evidence-based: `referenced` means a literal artifact path or unique basename occurs in the RE records; it is not a completed-analysis or security verdict.",
        "",
        "## Summary",
        "",
        f"- Artifacts: {summary['files']}",
        f"- Bytes: {summary['bytes']}",
        f"- Status: {summary['statuses']}",
        f"- Duplicate groups/files: {summary['duplicate_groups']}/{summary['duplicate_files']}",
        f"- Metadata-only files: {summary['metadata_only_files']}",
        f"- Scan errors: {summary['errors']}",
        "",
        "## By top-level directory",
        "",
        "| Directory | Artifacts |",
        "|---|---:|",
    ]
    lines.extend(f"| {_cell(name)} | {count} |" for name, count in summary["top_level"].items())
    lines.extend([
        "",
        "## Artifacts",
        "",
        "| Path | Size | Extension | Status | Handler | Duplicate | Metadata only | Evidence | Error |",
        "|---|---:|---|---|---|---|---|---|---|---|",
    ])
    for artifact in inventory.artifacts:
        lines.append(
            f"| {_cell(artifact.path)} | {artifact.size} | {_cell(artifact.extension)} "
            f"| {artifact.status} | {_cell(artifact.handler)} | {artifact.duplicate} "
            f"| {artifact.metadata_only} | {_cell(', '.join(artifact.evidence))} | {_cell(artifact.error)} |"
        )
    if inventory.errors:
        lines.extend(["", "## Scan errors", ""])
        lines.extend(f"- {_cell(error)}" for error in inventory.errors)
    return "\n".join(lines) + "\n"


def _main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Inventory artifacts and RE evidence coverage")
    parser.add_argument("root")
    parser.add_argument("--records")
    parser.add_argument("--hash", action="store_true", help="Hash files for duplicate detection")
    parser.add_argument("--json", required=True)
    parser.add_argument("--markdown", required=True)
    args = parser.parse_args(argv)
    inventory = scan_artifacts(args.root, args.records, hash_files=args.hash)
    Path(args.json).write_text(json.dumps(inventory_to_dict(inventory), indent=2, sort_keys=True) + "\n")
    Path(args.markdown).write_text(markdown_report(inventory))
    print(json.dumps(inventory.summary, sort_keys=True))


if __name__ == "__main__":
    _main()
