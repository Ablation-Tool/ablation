"""Safe extraction of signed Junos package archives."""
from __future__ import annotations

import hashlib
import json
import os
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path

from ablation.parsers.iso9660 import ISO9660
from ablation.parsers.junos_container import JunosISOInfo, decompress, probe


@dataclass(frozen=True)
class HashVerification:
    path: str
    expected: str
    actual: str
    valid: bool


@dataclass(frozen=True)
class JunosExtractionResult:
    package: str
    package_sha256: str
    payload: str
    iso: str
    root: str | None
    iso_info: JunosISOInfo
    hashes: tuple[HashVerification, ...]
    entries: int


def _parts(path: str) -> tuple[str, ...]:
    if path.startswith("/") or "\x00" in path:
        raise ValueError(f"Unsafe archive path: {path!r}")
    parts = tuple(part for part in path.split("/") if part not in ("", "."))
    if any(part == ".." for part in parts):
        raise ValueError(f"Unsafe archive path: {path!r}")
    return parts


def _link_target(member: tarfile.TarInfo) -> str:
    target = member.linkname
    if target.startswith("/") or any(part == ".." for part in target.split("/")):
        raise ValueError(f"Unsafe archive symlink {member.name!r} -> {target!r}")
    return target


def extract_tar_safely(package: str | Path, output_dir: str | Path) -> list[str]:
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    with tarfile.open(package, "r:*") as archive:
        for member in archive:
            parts = _parts(member.name)
            if not parts:
                continue
            destination = root.joinpath(*parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                destination.symlink_to(_link_target(member))
            elif member.islnk():
                source = root.joinpath(*_parts(member.linkname))
                if not source.is_file():
                    raise ValueError(f"Invalid archive hardlink {member.name!r} -> {member.linkname!r}")
                os.link(source, destination)
            elif member.isfile():
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"Cannot read archive member {member.name!r}")
                with source, open(destination, "wb") as output:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
                os.chmod(destination, member.mode & 0o7777)
            else:
                raise ValueError(f"Unsupported archive member type: {member.name!r}")
            extracted.append("/".join(parts))
    return extracted


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_embedded_hashes(root: str | Path) -> list[HashVerification]:
    base = Path(root)
    results: list[HashVerification] = []
    for manifest in sorted(base.rglob("*.sha1")):
        target = manifest.with_suffix("")
        if not target.is_file():
            raise ValueError(f"Missing hash target for {manifest}")
        expected = manifest.read_text().split()[0].lower()
        actual = hashlib.sha1()
        with open(target, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                actual.update(chunk)
        results.append(HashVerification(
            path=str(target.relative_to(base)),
            expected=expected,
            actual=actual.hexdigest(),
            valid=expected == actual.hexdigest(),
        ))
    return results


def extract_package(
    package: str | Path,
    output_dir: str | Path,
    extract_iso: bool = True,
) -> JunosExtractionResult:
    package_path = Path(package)
    output = Path(output_dir)
    contents = output / "package"
    extract_tar_safely(package_path, contents)
    hashes = tuple(verify_embedded_hashes(contents))
    payload = None
    info = None
    for candidate in contents.rglob("*"):
        if not candidate.is_file() or candidate.suffix in (".tgz", ".sha1", ".sig", ".esig"):
            continue
        try:
            info = probe(candidate)
        except (ValueError, OSError):
            continue
        payload = candidate
        break
    if payload is None or info is None:
        raise ValueError(f"No Junos compressed ISO payload found in {package_path}")
    iso = output / "payload.iso"
    decompress(payload, iso)
    root = None
    entries = 0
    if extract_iso:
        root_path = output / "root"
        with ISO9660(iso) as image:
            entries = len(image.extract_all(root_path))
        root = str(root_path)
    metadata = {
        "package": str(package_path),
        "package_sha256": _sha256(package_path),
        "payload": str(payload),
        "iso": str(iso),
        "root": root,
        "iso_info": asdict(info),
        "hashes": [asdict(result) for result in hashes],
        "entries": entries,
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2))
    return JunosExtractionResult(
        package=str(package_path),
        package_sha256=metadata["package_sha256"],
        payload=str(payload),
        iso=str(iso),
        root=root,
        iso_info=info,
        hashes=hashes,
        entries=entries,
    )
