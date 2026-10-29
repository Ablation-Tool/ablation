import json
from types import SimpleNamespace

import pytest

from ablation.cli import cmd_junos
from ablation.core.junos_package import HashVerification


def test_junos_inventory_cli(tmp_path, capsys):
    (tmp_path / "file").write_bytes(b"data")
    output = tmp_path / "manifest.json"
    args = SimpleNamespace(junos_command="inventory", root=str(tmp_path), json=str(output))

    cmd_junos(args)

    assert json.loads(capsys.readouterr().out)["files"] == 1
    assert json.loads(output.read_text())["file"]["sha256"]


def test_junos_diff_cli(tmp_path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "changed").write_bytes(b"old")
    (new / "changed").write_bytes(b"new")
    output = tmp_path / "diff.json"
    args = SimpleNamespace(
        junos_command="diff",
        old=str(old),
        new=str(new),
        functions=None,
        top_k=0,
        json=str(output),
    )

    cmd_junos(args)

    assert json.loads(output.read_text())["summary"]["changed"] == 1


def test_junos_verify_require_all(tmp_path, monkeypatch):
    invalid = HashVerification("payload", "a", "b", False)
    monkeypatch.setattr("ablation.core.junos_package.verify_embedded_hashes", lambda root: [invalid])
    monkeypatch.setattr("ablation.core.junos_signature.verify_package_directory", lambda root: [])
    args = SimpleNamespace(junos_command="verify", root=str(tmp_path), json=None, require_all=True)

    with pytest.raises(SystemExit):
        cmd_junos(args)


def test_junos_gencfg_cli(capsys):
    message = bytearray(0x11C)
    message[0:2] = (0x89).to_bytes(2, "big")
    message[2:4] = (4).to_bytes(2, "big")
    message[4:8] = (3).to_bytes(4, "big")
    message[12:16] = (0x98).to_bytes(4, "big")
    message[32:34] = (4).to_bytes(2, "big")
    args = SimpleNamespace(junos_command="gencfg", message=message.hex(), family="vrf-group", list_schemas=False)

    cmd_junos(args)

    assert json.loads(capsys.readouterr().out)["valid"]


def test_junos_target_cli(capsys, monkeypatch):
    monkeypatch.setattr(
        "ablation.analyzers.junos_target.describe_mips_elf",
        lambda binary: "mips32/o32 (mips64r2 instructions, big-endian)",
    )
    args = SimpleNamespace(junos_command="target", binary="flowd_octeon")

    cmd_junos(args)

    report = json.loads(capsys.readouterr().out)
    assert report["profile"] == "junos-octeon-o32"
    assert "mips32/o32" in report["elf"]
