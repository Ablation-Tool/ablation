import json

import pytest

from ablation.analyzers.artifact_inventory import (
    inventory_to_dict,
    markdown_report,
    scan_artifacts,
)


def test_inventory_coverage_duplicates_and_incomplete(tmp_path):
    root = tmp_path / "artifacts"
    records = tmp_path / "records"
    (root / "a").mkdir(parents=True)
    (root / "b").mkdir()
    records.mkdir()
    (root / "a" / "foo.bin").write_bytes(b"same")
    (root / "b" / "foo.bin").write_bytes(b"same")
    (root / "unique.pdi").write_bytes(b"pdi")
    (root / "large.pdi").write_bytes(b"partial")
    (root / "large.pdi.aria2").write_bytes(b"marker")
    (root / "plain.txt").write_text("unreviewed")
    (records / "target_re.py").write_text("a/foo.bin and unique.pdi")
    (records / "cern_artifact_coverage.md").write_text("plain.txt b/foo.bin")
    (records / "coverage_re.py").write_text("plain.txt b/foo.bin")

    inventory = scan_artifacts(root, records, hash_files=True)
    artifacts = {artifact.path: artifact for artifact in inventory.artifacts}

    assert artifacts["a/foo.bin"].status == "referenced"
    assert artifacts["b/foo.bin"].status == "unreviewed"
    assert artifacts["a/foo.bin"].duplicate
    assert artifacts["b/foo.bin"].duplicate
    assert artifacts["unique.pdi"].status == "referenced"
    assert artifacts["unique.pdi"].handler == "VersalPdi"
    assert artifacts["large.pdi"].status == "incomplete"
    assert artifacts["large.pdi.aria2"].status == "incomplete"
    assert artifacts["plain.txt"].status == "unreviewed"
    assert inventory.summary["files"] == 6
    assert inventory.summary["duplicate_groups"] == 1

    report = markdown_report(inventory)
    assert "Artifact coverage matrix" in report
    assert "a/foo.bin" in report
    assert "not a completed-analysis" in report


def test_symlinks_and_secret_files_are_metadata_only(tmp_path, monkeypatch):
    root = tmp_path / "artifacts"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "hidden.bin").write_bytes(b"outside")
    (root / ".env").write_text("do-not-read")
    (root / "link.bin").symlink_to(outside / "hidden.bin")
    (root / "linked-directory").symlink_to(outside, target_is_directory=True)

    import ablation.analyzers.artifact_inventory as module
    original = module._sha256

    def guarded(path):
        assert path.name != ".env"
        return original(path)

    monkeypatch.setattr(module, "_sha256", guarded)
    inventory = scan_artifacts(root, hash_files=True)
    artifacts = {artifact.path: artifact for artifact in inventory.artifacts}

    assert artifacts[".env"].metadata_only
    assert artifacts[".env"].sha256 == ""
    assert artifacts["link.bin"].kind == "symlink"
    assert artifacts["link.bin"].metadata_only
    assert "hidden.bin" not in artifacts


def test_deterministic_json_and_invalid_root(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "one.txt").write_text("one")
    first = inventory_to_dict(scan_artifacts(root))
    second = inventory_to_dict(scan_artifacts(root))
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["summary"]["statuses"] == {"unreviewed": 1}

    with pytest.raises(FileNotFoundError):
        scan_artifacts(tmp_path / "missing")
    records = tmp_path / "records"
    records.mkdir()
    with pytest.raises(ValueError, match="evidence path is not a directory"):
        scan_artifacts(root, root / "one.txt")
