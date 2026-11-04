from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from . import __version__
from .detect import detect


SCHEMA_VERSION = 1
SAMPLE_SIZE = 65536
HASH_CHUNK_SIZE = 1024 * 1024


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def artifact_id(relative_path, identity):
    return "art-" + hashlib.sha256(relative_path.encode("utf-8") + b"\x00" + identity.encode("utf-8")).hexdigest()[:24]


def base_record(relative_path, kind):
    return {
        "schema_version": SCHEMA_VERSION,
        "id": "",
        "path": relative_path,
        "kind": kind,
        "size_bytes": None,
        "sha256": None,
        "format": "unknown",
        "architecture": "unknown",
        "endianness": "unknown",
        "artifact_class": "data",
        "status": "unidentified",
        "analysis_status": "not_recorded",
        "detection": {"method": "not-inspected", "evidence": ""},
    }


def error_record(relative_path, kind, message):
    record = base_record(relative_path, "error")
    record.update({
        "id": artifact_id(relative_path, f"error:{kind}:{message}"),
        "artifact_class": "error",
        "status": "error",
        "scan_error": message,
        "source_kind": kind,
    })
    return record


def inspect_file(path, relative_path):
    record = base_record(relative_path, "file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return error_record(relative_path, "special", "opened entry is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            sample = stream.read(SAMPLE_SIZE)
            digest = hashlib.sha256()
            digest.update(sample)
            while chunk := stream.read(HASH_CHUNK_SIZE):
                digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            return error_record(relative_path, "file", "file changed while it was being hashed")
        content_hash = digest.hexdigest()
        detection = detect(sample, before.st_size, path.name)
        record.update({
            "id": artifact_id(relative_path, content_hash),
            "size_bytes": before.st_size,
            "sha256": content_hash,
            "format": detection.format,
            "architecture": detection.architecture,
            "endianness": detection.endianness,
            "artifact_class": detection.artifact_class,
            "status": "identified" if detection.format != "unknown" else "unidentified",
            "detection": {"method": detection.method, "evidence": detection.evidence},
        })
        return record
    finally:
        os.close(descriptor)


def inspect_symlink(path, relative_path):
    target = os.readlink(path)
    record = base_record(relative_path, "symlink")
    record.update({
        "id": artifact_id(relative_path, "symlink:" + target),
        "artifact_class": "symlink",
        "status": "identified",
        "link_target": target,
        "detection": {"method": "lstat", "evidence": "symbolic link; target not followed"},
    })
    return record


def inspect_special(relative_path):
    record = base_record(relative_path, "special")
    record.update({
        "id": artifact_id(relative_path, "special"),
        "artifact_class": "special",
        "status": "identified",
        "detection": {"method": "lstat", "evidence": "non-regular filesystem entry; content not opened"},
    })
    return record


def is_excluded(path, output):
    return path == output or output in path.parents


def scan(root, output):
    root = Path(root).expanduser().resolve()
    output = Path(output).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"scan root is not a directory: {root}")
    if root == output:
        raise ValueError("output directory must not be the scan root")
    records = []
    directory_count = 0

    def walk(directory):
        nonlocal directory_count
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: os.fsencode(item.name))
        except OSError as error:
            relative = Path(directory).relative_to(root).as_posix()
            records.append(error_record(relative, "directory", str(error)))
            return
        for entry in entries:
            path = Path(entry.path)
            if is_excluded(path, output):
                continue
            relative = path.relative_to(root).as_posix()
            try:
                if entry.is_symlink():
                    records.append(inspect_symlink(path, relative))
                elif entry.is_dir(follow_symlinks=False):
                    directory_count += 1
                    walk(path)
                elif entry.is_file(follow_symlinks=False):
                    try:
                        records.append(inspect_file(path, relative))
                    except OSError as error:
                        records.append(error_record(relative, "file", str(error)))
                else:
                    records.append(inspect_special(relative))
            except OSError as error:
                records.append(error_record(relative, "unknown", str(error)))

    walk(root)
    records.sort(key=lambda record: os.fsencode(record["path"]))
    regular = [record for record in records if record["kind"] == "file"]
    summary = {
        "schema_version": SCHEMA_VERSION,
        "tool": "METRIX",
        "tool_version": __version__,
        "generated_utc": utc_now(),
        "root": str(root),
        "output": str(output),
        "symlinks_followed": False,
        "artifacts": len(records),
        "regular_files": len(regular),
        "hashed_files": sum(record["sha256"] is not None for record in regular),
        "directories": directory_count,
        "symlinks": sum(record["kind"] == "symlink" for record in records),
        "special_entries": sum(record["kind"] == "special" for record in records),
        "errors": sum(record["status"] == "error" for record in records),
        "total_file_bytes": sum(record["size_bytes"] for record in regular),
        "formats": dict(sorted(Counter(record["format"] for record in records).items())),
        "architectures": dict(sorted(Counter(record["architecture"] for record in records).items())),
        "artifact_classes": dict(sorted(Counter(record["artifact_class"] for record in records).items())),
        "statuses": dict(sorted(Counter(record["status"] for record in records).items())),
        "analysis_status": "not_recorded",
    }
    return records, summary


def atomic_write(path, callback):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            callback(stream)
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def write_scan(output, records, summary):
    output.mkdir(parents=True, exist_ok=True)
    atomic_write(output / "artifacts.jsonl", lambda stream: stream.writelines(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records))
    atomic_write(output / "summary.json", lambda stream: stream.write(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True) + "\n"))


def load_records(output):
    path = output / "artifacts.jsonl"
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"invalid JSON in {path} line {number}: {error}") from error
