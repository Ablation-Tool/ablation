from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile

from .geometry import VerificationReport, verify
from .model import Scene
from .render import scene_to_svg
from .vdi import scene_from_metafile, scene_to_metafile


DEVICE_PROFILES = {
    "cga": (320, 200),
    "vga": (640, 480),
    "ndc": (32767, 32767),
}
MAX_RUN_BYTES = 256 * 1024 * 1024


def _json_bytes(document):
    return (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path, data):
    if path.is_symlink():
        raise ValueError(f"run artifact must not be a symbolic link: {path}")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def verify_vdi(scene, data=None):
    if data is None:
        data = scene_to_metafile(scene)
    source_report = verify(scene)
    recovered = scene_from_metafile(data, scene.constraints)
    report = verify(recovered)
    source_ids = [item["id"] for item in scene.objects]
    recovered_ids = [item["id"] for item in recovered.objects]
    invariants = {
        "object_ids_preserved": source_ids == recovered_ids,
        "object_count_preserved": len(source_ids) == len(recovered_ids),
        "constraint_outcomes_preserved": (
            [item["passed"] for item in source_report.results]
            == [item["passed"] for item in report.results]
        ),
    }
    return VerificationReport(report.scene_id, report.results, invariants)


def verify_device(scene, profile, dimensions=None):
    if dimensions is None:
        if profile not in DEVICE_PROFILES:
            raise ValueError(f"unknown device profile: {profile}")
        dimensions = DEVICE_PROFILES[profile]
    scaled = scene.rescaled(*dimensions, scene_id=f"{scene.document['id']}-{profile}")
    source_report = verify(scaled)
    data = scene_to_metafile(scaled)
    vdi_report = verify_vdi(scaled, data)
    return {
        "profile": profile,
        "width": dimensions[0],
        "height": dimensions[1],
        "passed": source_report.passed and vdi_report.passed,
        "invariants": vdi_report.invariants,
        "source": source_report.to_dict(),
        "vdi": vdi_report.to_dict(),
    }


def trajectory_bytes(records):
    records = list(records)
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("trajectory records must be JSON objects")
    return b"".join(
        (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for record in records
    )


def build_run(scene, trajectory=()):
    source_report = verify(scene)
    source_vdi = scene_to_metafile(scene)
    vdi_report = verify_vdi(scene, source_vdi)
    devices = {}
    artifacts = {
        "scene.json": scene.json().encode("utf-8"),
        "scene.gem": source_vdi,
        "preview.svg": scene_to_svg(scene).encode("utf-8"),
        "source-report.json": _json_bytes(source_report.to_dict()),
        "vdi-report.json": _json_bytes(vdi_report.to_dict()),
        "trajectory.jsonl": trajectory_bytes(trajectory),
    }
    for profile in DEVICE_PROFILES:
        report = verify_device(scene, profile)
        devices[profile] = report
        artifacts[f"scene-{profile}.gem"] = scene_to_metafile(
            scene.rescaled(*DEVICE_PROFILES[profile], scene_id=f"{scene.document['id']}-{profile}")
        )
    artifacts["device-report.json"] = _json_bytes(devices)
    passed = source_report.passed and vdi_report.passed and all(item["passed"] for item in devices.values())
    manifest = {
        "schema_version": 1,
        "format": "gem-run",
        "scene_id": scene.document["id"],
        "scene_digest": scene.digest(),
        "passed": passed,
        "scope": "bounded Spatial IR; source and VDI geometry; CGA/VGA/NDC profiles",
        "source_constraints": {
            "passed": source_report.to_dict()["constraints_passed"],
            "total": len(scene.constraints),
        },
        "artifacts": {name: _digest(data) for name, data in artifacts.items()},
    }
    artifacts["run.json"] = _json_bytes(manifest)
    return artifacts, manifest, source_report, vdi_report, devices


def export_run(scene, path, trajectory=(), overwrite=False):
    expanded = Path(path).expanduser()
    if expanded.is_symlink():
        raise ValueError(f"run directory must not be a symbolic link: {expanded}")
    path = expanded.resolve()
    if path.exists() and (not path.is_dir() or any(path.iterdir())) and not overwrite:
        raise FileExistsError(f"run directory is not empty: {path}")
    artifacts, manifest, source_report, vdi_report, devices = build_run(scene, trajectory)
    path.mkdir(parents=True, exist_ok=True)
    lock_path = path / ".export.lock"
    try:
        with lock_path.open("xb"):
            pass
    except FileExistsError as error:
        raise FileExistsError(f"run directory is already being written: {path}") from error
    try:
        for name, data in artifacts.items():
            _atomic_write(path / name, data)
    finally:
        lock_path.unlink(missing_ok=True)
    return RunResult(path, scene, source_report, vdi_report, devices, manifest)


def next_run_directory(base, scene):
    base = Path(base).expanduser().resolve()
    prefix = f"gem-{scene.digest()[:16]}"
    for index in range(1, 100000):
        path = base / f"{prefix}-{index:04d}"
        if not path.exists():
            return path
    raise FileExistsError(f"no available GEM run directory under {base}")


def write_failed_run(path, trajectory, error):
    path = Path(path).expanduser().resolve()
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise FileExistsError(f"run directory is not empty: {path}")
    path.mkdir(parents=True, exist_ok=True)
    (path / "trajectory.jsonl").write_bytes(trajectory_bytes(trajectory))
    (path / "error.json").write_bytes(_json_bytes({"passed": False, "error": str(error)[:4000]}))
    return path


@dataclass(frozen=True)
class RunResult:
    path: Path
    scene: Scene
    source: object
    vdi: object
    devices: dict
    manifest: dict

    @property
    def passed(self):
        return self.manifest["passed"]

    def scope(self):
        counts = self.manifest["source_constraints"]
        return (
            f"source+VDI {'verified' if self.passed else 'checked with failures'}, "
            f"{counts['passed']}/{counts['total']} constraints; CGA/VGA/NDC profiles"
        )


@dataclass(frozen=True)
class ReplayResult:
    path: Path
    manifest: dict
    source: dict
    vdi: dict
    devices: dict
    matches_recorded: bool

    @property
    def passed(self):
        return (
            self.source["passed"] and self.vdi["passed"]
            and all(report["passed"] for report in self.devices.values())
        )

    def to_dict(self):
        return {
            "run": str(self.path),
            "schema_version": self.manifest["schema_version"],
            "scene_digest": self.manifest["scene_digest"],
            "passed": self.passed,
            "matches_recorded": self.matches_recorded,
            "source": self.source,
            "vdi": self.vdi,
            "devices": self.devices,
        }


def _read_artifact(path, name, expected_digest):
    data = (path / name).read_bytes()
    if _digest(data) != expected_digest:
        raise ValueError(f"GEM run artifact hash mismatch: {name}")
    return data


def replay(path):
    path = Path(path).expanduser().resolve()
    manifest_path = path / "run.json"
    if manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError("GEM run manifest is too large")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        not isinstance(manifest, dict) or manifest.get("schema_version") != 1
        or manifest.get("format") != "gem-run" or not isinstance(manifest.get("artifacts"), dict)
    ):
        raise ValueError("invalid GEM run manifest")
    required = {
        "scene.json", "scene.gem", "preview.svg", "source-report.json",
        "vdi-report.json", "device-report.json", "trajectory.jsonl",
        *(f"scene-{profile}.gem" for profile in DEVICE_PROFILES),
    }
    if set(manifest["artifacts"]) != required:
        raise ValueError("GEM run manifest has an unexpected artifact inventory")
    total_bytes = 0
    for name, digest in manifest["artifacts"].items():
        if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError(f"invalid GEM run artifact digest: {name}")
        artifact_path = path / name
        if artifact_path.is_symlink():
            raise ValueError(f"GEM run artifact must not be a symbolic link: {name}")
        total_bytes += artifact_path.stat().st_size
    if total_bytes > MAX_RUN_BYTES:
        raise ValueError("GEM run artifacts are too large")
    artifacts = {
        name: _read_artifact(path, name, digest)
        for name, digest in manifest["artifacts"].items()
    }
    scene = Scene.from_dict(json.loads(artifacts["scene.json"]))
    if scene.digest() != manifest.get("scene_digest"):
        raise ValueError("GEM run scene identity does not match its manifest")
    source = verify(scene).to_dict()
    vdi = verify_vdi(scene, artifacts["scene.gem"]).to_dict()
    devices = {}
    for profile, dimensions in DEVICE_PROFILES.items():
        report = verify_device(scene, profile, dimensions)
        expected_data = scene_to_metafile(
            scene.rescaled(*dimensions, scene_id=f"{scene.document['id']}-{profile}")
        )
        if artifacts[f"scene-{profile}.gem"] != expected_data:
            raise ValueError(f"GEM run device scene mismatch: {profile}")
        devices[profile] = report
    recorded = {
        "source": json.loads(artifacts["source-report.json"]),
        "vdi": json.loads(artifacts["vdi-report.json"]),
        "devices": json.loads(artifacts["device-report.json"]),
    }
    matches = recorded == {"source": source, "vdi": vdi, "devices": devices}
    return ReplayResult(path, manifest, source, vdi, devices, matches)
