import json
from pathlib import Path

from ablation.analyzers.gencfg_provenance import build_provenance_graph
from ablation.analyzers.insn_mips import make_insn
from ablation.analyzers.junos_function_diff import (
    compare_functions, comparison_cache_key, normalize_mips_instruction,
)
from ablation.analyzers.mips_function import MipsFunction
from ablation.analyzers.mips_ownership import analyze_function, analyze_ownership


def _function(path, va, instructions, symbols=None):
    code = [make_insn(address, mnemonic, operands) for address, mnemonic, operands in instructions]
    return MipsFunction(Path(path), va, len(code) * 4, "test_function", tuple(code), symbols or {})


def test_function_diff_normalizes_relocation_and_stripped_calls(monkeypatch):
    old = _function("old", 0x1000, [
        (0x1000, "addiu", "$sp, $sp, -0x20"),
        (0x1004, "beq", "$a0, $zero, 0x100c"),
        (0x1008, "nop", ""),
        (0x100C, "jal", "0x2000"),
        (0x1010, "nop", ""),
        (0x1014, "jr", "$ra"),
        (0x1018, "nop", ""),
    ], {0x2000: "mod_free"})
    new = _function("new", 0x5000, [
        (0x5000, "addiu", "$sp, $sp, -0x40"),
        (0x5004, "beq", "$a0, $zero, 0x500c"),
        (0x5008, "nop", ""),
        (0x500C, "jal", "0x9000"),
        (0x5010, "nop", ""),
        (0x5014, "jr", "$ra"),
        (0x5018, "nop", ""),
    ])
    monkeypatch.setattr(
        "ablation.analyzers.junos_function_diff.load_mips_function",
        lambda path, va, size, max_size: old if path == "old" else new,
    )
    monkeypatch.setattr("ablation.analyzers.junos_function_diff.file_sha256", lambda path: path)

    result = compare_functions("old", "new", old.va, new.va)

    assert result["equivalent"]
    assert result["summary"]["matching_instructions"] == 7
    assert result["old"]["callees"] == ["mod_free"]
    assert result["new"]["callees"] == ["0x9000"]


def test_function_diff_cache_key_is_content_addressed(tmp_path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.write_bytes(b"old")
    new.write_bytes(b"new")
    key = comparison_cache_key(old, new, 0x1000, 0x2000, 100, 100)
    assert key == comparison_cache_key(old, new, 0x1000, 0x2000, 100, 100)
    new.write_bytes(b"changed")
    assert key != comparison_cache_key(old, new, 0x1000, 0x2000, 100, 100)


def test_ownership_detects_double_free_and_subsequent_dereference():
    function = _function("test", 0x1000, [
        (0x1000, "move", "$s0, $a0"),
        (0x1004, "jal", "0x2000"),
        (0x1008, "nop", ""),
        (0x100C, "move", "$a0, $s0"),
        (0x1010, "jal", "0x2000"),
        (0x1014, "nop", ""),
        (0x1018, "lw", "$v0, 0($s0)"),
        (0x101C, "jr", "$ra"),
        (0x1020, "nop", ""),
    ], {0x2000: "mod_free"})

    result = analyze_function(function)

    assert {finding["kind"] for finding in result["findings"]} == {"double_free", "use_after_free"}
    assert [event["kind"] for event in result["events"]].count("free") == 2


def test_ownership_correlates_global_free_with_deferred_callback(monkeypatch):
    owner = _function("owner", 0x1000, [
        (0x1000, "lui", "$v0, 0x1e61"),
        (0x1004, "addiu", "$v0, $v0, 0x6c74"),
        (0x1008, "lw", "$s0, 0($v0)"),
        (0x100C, "move", "$a0, $s0"),
        (0x1010, "jal", "0x2000"),
        (0x1014, "nop", ""),
        (0x1018, "jr", "$ra"),
        (0x101C, "nop", ""),
    ], {0x2000: "mod_free"})
    callback = _function("callback", 0x5000, [
        (0x5000, "lui", "$v0, 0x1e61"),
        (0x5004, "addiu", "$v0, $v0, 0x6c74"),
        (0x5008, "lw", "$s0, 0($v0)"),
        (0x500C, "lw", "$v0, 0($s0)"),
        (0x5010, "jr", "$ra"),
        (0x5014, "nop", ""),
    ], {0x2000: "mod_free"})
    monkeypatch.setattr(
        "ablation.analyzers.mips_ownership.load_mips_function",
        lambda binary, va, size: owner if va == owner.va else callback,
    )

    result = analyze_ownership("test", [
        {"name": "owner", "va": owner.va, "size": owner.size},
        {"name": "callback", "va": callback.va, "size": callback.size, "role": "deferred_callback"},
    ])

    kinds = {finding["kind"] for finding in result["findings"]}
    assert {"dangling_global_pointer", "deferred_use_after_free"} <= kinds


def test_provenance_graph_verifies_direct_and_indirect_call_sites(monkeypatch):
    function = _function("source", 0x1000, [
        (0x1000, "jal", "0x2000"),
        (0x1004, "nop", ""),
        (0x1008, "jalr", "$t9"),
        (0x100C, "nop", ""),
        (0x1010, "jr", "$ra"),
        (0x1014, "nop", ""),
    ])
    monkeypatch.setattr("ablation.analyzers.gencfg_provenance.load_mips_function", lambda *args: function)
    spec = {
        "nodes": [
            {"id": "producer", "binary": "nsd", "va": "0x1000", "size": 24, "role": "producer"},
            {"id": "relay", "binary": "nsd", "va": "0x2000", "size": 24},
            {"id": "consumer", "binary": "flowd", "va": "0x3000", "size": 24, "role": "consumer"},
        ],
        "edges": [
            {"source": "producer", "target": "relay", "kind": "direct_call", "call_va": "0x1000"},
            {"source": "relay", "target": "consumer", "kind": "indirect_call", "call_va": "0x1008"},
        ],
        "runtime_unknowns": ["policy registrations"],
    }

    result = build_provenance_graph("/junos", spec)

    assert result["edges"][0]["verification"]["status"] == "verified"
    assert result["edges"][1]["verification"]["status"] == "call_site_verified"
    assert result["producer_consumer_paths"] == [["producer", "relay", "consumer"]]
    assert result["runtime_unknowns"] == ["policy registrations"]


def test_gencfg_encode_cli(capsys):
    from types import SimpleNamespace
    from ablation.cli import cmd_junos

    args = SimpleNamespace(
        junos_command="gencfg", message=None, family="vrf-group", list_schemas=False,
        encode=True, group_id=7, lsys_id=0, operation=2, vrf=[10],
    )
    cmd_junos(args)
    output = json.loads(capsys.readouterr().out)
    assert output["validation"]["valid"]
    assert output["validation"]["blob"]["entries"][0]["vrf_id"] == 10


def test_message_provenance_traces_arguments_and_delay_slot():
    from ablation.analyzers.mips_message_provenance import slice_call_arguments

    function = _function("source", 0x1000, [
        (0x1000, "addiu", "$s0, $a0, 0xc"),
        (0x1004, "lw", "$v1, 0x14($s0)"),
        (0x1008, "sw", "$v1, 0x20($sp)"),
        (0x100C, "move", "$a1, $s0"),
        (0x1010, "lw", "$a2, 0x20($sp)"),
        (0x1014, "jal", "0x2000"),
        (0x1018, "addiu", "$a3, $zero, 1"),
    ])

    result = slice_call_arguments(function, 0x1014, ("a1", "a2", "a3"))

    assert result["arguments"] == {"$a1": "$a0 + 0xc", "$a2": "lw[($a0 + 0xc)+0x14]", "$a3": "$zero + 0x1"}
    assert result["boundary"]["kind"] == "function_entry"


def test_message_provenance_stops_at_control_flow_join():
    from ablation.analyzers.mips_message_provenance import slice_call_arguments

    function = _function("source", 0x1000, [
        (0x1000, "addiu", "$s0, $a0, 0xc"),
        (0x1004, "beq", "$v0, $zero, 0x100c"),
        (0x1008, "nop", ""),
        (0x100C, "move", "$a1, $s0"),
        (0x1010, "jal", "0x2000"),
        (0x1014, "nop", ""),
    ])

    result = slice_call_arguments(function, 0x1010, ("a1",))

    assert result["arguments"] == {"$a1": "$s0"}
    assert result["boundary"] == {
        "kind": "control_flow", "address": "0x1004",
        "instruction": "0x1004: beq $2, $0, 0x100c",
    }
