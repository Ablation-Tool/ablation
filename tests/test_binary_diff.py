from ablation.analyzers.binary_diff import (
    FunctionRecord,
    build_manifest,
    diff_manifests,
    match_functions,
    normalize_instruction,
    normalize_string,
)


def test_manifest_diff_classifies_changes(tmp_path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "same").write_bytes(b"same")
    (old / "changed").write_bytes(b"old")
    (old / "removed").write_bytes(b"removed")
    (new / "same").write_bytes(b"same")
    (new / "changed").write_bytes(b"newer")
    (new / "added").write_bytes(b"added")

    result = diff_manifests(build_manifest(old), build_manifest(new))

    assert result["summary"] == {
        "added": 1,
        "removed": 1,
        "changed": 1,
        "unchanged": 1,
        "changed_elf": 0,
    }
    assert {change["path"] for change in result["changes"]} == {"added", "changed", "removed"}


def test_release_normalization():
    assert normalize_string("built 2019-02-22 23:07:21 UTC") == "built <release>"
    assert normalize_string("15.1X49-D170.4") == "<release>"
    assert normalize_instruction("JAL", "0x4262b4") == "jal <addr>"
    assert normalize_instruction("ADDIU", "a0, zero, 512") == "addiu a0, zero, <imm>"


def _record(name: str, va: int, signature: str) -> FunctionRecord:
    return FunctionRecord(name, va, 16, signature, ("instruction",))


def test_function_matching_names_and_normalized_code():
    old = {
        "same": _record("same", 0x1000, "a"),
        "changed": _record("changed", 0x1010, "b"),
        "removed": _record("removed", 0x1020, "c"),
        "old_address": _record("old_address", 0x1030, "d"),
    }
    new = {
        "same": _record("same", 0x2000, "a"),
        "changed": _record("changed", 0x2010, "e"),
        "added": _record("added", 0x2020, "f"),
        "new_address": _record("new_address", 0x2030, "d"),
    }

    result = match_functions(old, new)

    assert result["summary"] == {"changed": 1, "unchanged": 2, "added": 1, "removed": 1}
    assert result["added"] == ["added"]
    assert result["removed"] == ["removed"]
    assert any(item.get("matched_name") == "new_address" for item in result["unchanged"])
